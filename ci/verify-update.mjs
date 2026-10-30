import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import { lstat, mkdir, mkdtemp, open, readFile, realpath, stat } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  VerificationFailure, check, connectCdp, downloadPinned, emitReceipt, evaluate,
  ensureFreshHost, extractZip, findOwnedPid, findOwnedPids, loadPins, requireCiContext,
  run, sha256File, terminateOwned, unusedPort, verifyApp, waitFor,
} from "./runtime.mjs";

export const SCENARIOS = Object.freeze([
  "positive", "offline", "unavailable", "interrupted", "checksum", "downgrade", "signature",
]);
const PHASES = ["fresh_host", "download", "base_verify", "candidate_verify", "signature_fixture_verify",
  "base_bootstrap", "base_spawn", "base_diagnostic_connect", "base_debugger_enable", "base_waiting_release", "base_pause_wait",
  "base_attest", "base_feed", "base_debugger_resume", "base_debugger_disable", "preload_ready", "seed", "negative_check", "signature_native_preflight", "signature_restart", "positive_download", "native_install",
  "replacement", "preservation", "cleanup", "completed"];

export function parseScenario(args) {
  check(args.length === 2 && args[0] === "--scenario" && SCENARIOS.includes(args[1]), "scenario_required");
  return args[1];
}

export function loopbackUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new VerificationFailure("unverified", "loopback_url_invalid"); }
  check(url.protocol === "http:" && url.hostname === "127.0.0.1" && /^\d+$/.test(url.port) &&
    !url.username && !url.password && !url.hash, "loopback_url_invalid");
  return url;
}

export function byteRange(value, size) {
  check(Number.isSafeInteger(size) && size > 0, "range_size_invalid");
  if (!value) return { start: 0, end: size - 1, length: size, partial: false };
  const match = /^bytes=(\d+)-(\d*)$/.exec(value);
  if (!match) return undefined;
  const start = Number(match[1]);
  const end = match[2] ? Math.min(Number(match[2]), size - 1) : size - 1;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || start > end || start >= size) return undefined;
  return { start, end, length: end - start + 1, partial: true };
}

export function metadata({ version, name, bytes, sha512 }) {
  check(/^\d+\.\d+\.\d+$/.test(version) && /^Program-AI-Desktop-mac-(arm64|x64)\.(?:[a-z-]+\.)?zip$/.test(name) &&
    Number.isSafeInteger(bytes) && bytes > 0 && /^[A-Za-z0-9+/]{86}==$/.test(sha512), "feed_metadata_invalid");
  return `version: ${version}\nfiles:\n  - url: ${name}\n    sha512: ${sha512}\n    size: ${bytes}\nreleaseDate: '2026-10-29T00:00:00.000Z'\n`;
}

export function updaterObservation(value) {
  const statuses = ["disabled", "idle", "checking", "downloading", "ready", "up-to-date", "installing", "error"];
  if (!value || !statuses.includes(value.status)) return { status: "unknown", errorClass: "none" };
  const message = value.status === "error" && typeof value.message === "string" ? value.message : "";
  const errorClass = /checksum|sha512|sha256|digest/i.test(message) ? "checksum" :
    /signature|code.?sign|publisher|trust|shipit|err_updater_invalid_signature/i.test(message) ? "signature" :
    /network|socket|connect|download|http|offline|timeout/i.test(message) ? "network" : message ? "other" : "none";
  return { status: value.status, errorClass,
    ...(typeof value.version === "string" && /^\d+\.\d+\.\d+$/.test(value.version) ? { version: value.version } : {}) };
}

export function rejectionOutcome(scenario, observed, traffic) {
  check(SCENARIOS.includes(scenario) && scenario !== "positive", "scenario_invalid");
  // On macOS with autoInstallOnAppQuit=false, ready means downloaded, NOT
  // Squirrel signature validation. Only signatureInstallOutcome can attest it.
  if (scenario === "signature") return "unverified";
  if (scenario === "downgrade") {
    if (observed.status === "ready" || observed.status === "installing" || traffic.zip > 0) return "failed";
    return observed.status === "up-to-date" && traffic.metadata > 0 ? "passed" : "unverified";
  }
  if (observed.status === "ready" || observed.status === "installing") return "failed";
  if (observed.status !== "error" || traffic.metadata < 1) return "unverified";
  if (["offline", "unavailable"].includes(scenario)) return "passed";
  if (scenario === "interrupted") return traffic.interrupted > 0 && traffic.sent > 0 ? "passed" : "unverified";
  if (scenario === "checksum") return traffic.corrupted > 0 && traffic.sent >= traffic.expectedBytes &&
    observed.errorClass === "checksum" ? "passed" : "unverified";
  return "unverified";
}

// Observe native events only: never replace checks, feed, quit, install or
// listeners owned by the product/SDK. SQRLCodeSignatureErrorDidNotPass=-1 and
// CouldNotCreateStaticCode=-2 are Squirrel.Mac's actual signature error enums.
export function createNativeSignatureObserver(native, app) {
  let errors = 0, signatureErrors = 0, signatureCode = null, downloaded = false, beforeQuit = false;
  const failed = (error) => {
    errors = Math.min(16, errors + 1);
    if (error?.domain === "SQRLCodeSignatureErrorDomain" && [-1, -2].includes(error.code)) {
      signatureErrors = Math.min(16, signatureErrors + 1); signatureCode = error.code;
    }
  };
  const accepted = () => { downloaded = true; };
  const quitting = () => { beforeQuit = true; };
  native.on("error", failed); native.on("update-downloaded", accepted); app.on("before-quit", quitting);
  return {
    read: () => ({ errors, signatureErrors, signatureCode, downloaded, beforeQuit }),
    close() { native.removeListener("error", failed); native.removeListener("update-downloaded", accepted); app.removeListener("before-quit", quitting); },
  };
}

export function signatureInstallOutcome({ native, attempt, originalPid, baseAsar, sidecarUnchanged, completePayload }) {
  if (!originalPid || !baseAsar || !sidecarUnchanged || native?.downloaded || native?.beforeQuit || attempt?.resolved) return "failed";
  return completePayload === true && attempt?.rejected === true && native?.errors >= 1 && native.errors < 16 &&
    native.signatureErrors === native.errors && [-1, -2].includes(native.signatureCode) ? "passed" : "unverified";
}

function nativeProbe(expected, action, factory) {
  const require = process.getBuiltinModule("module").createRequire(process.resourcesPath + "/app.asar/package.json");
  const electron = require("electron");
  if (process.pid !== expected.pid || process.execPath !== expected.executable || process.resourcesPath !== expected.resources ||
    !electron.app.isPackaged || electron.app.getVersion() !== expected.version) throw new Error("owned_scope_required");
  const key = Symbol.for("program-ai-public-native-signature-observer");
  if (action === "arm") {
    if (globalThis[key]) throw new Error("native_observer_already_armed");
    globalThis[key] = factory(electron.autoUpdater, electron.app);
  }
  const observer = globalThis[key];
  if (!observer) throw new Error("native_observer_missing");
  const result = observer.read();
  if (action === "close") { observer.close(); delete globalThis[key]; }
  return result;
}

function probeExpression(expected, action) {
  check(["arm", "read", "close"].includes(action), "native_observer_action_invalid");
  return `(${nativeProbe.toString()})(${JSON.stringify(expected)},${JSON.stringify(action)},(${createNativeSignatureObserver.toString()}))`;
}

const INSTALL_ATTEMPT = "program-ai-public-native-signature-install";
function signaturePreloadAttempt(action, key) {
  const symbol = Symbol.for(key);
  if (action === "start") {
    if (globalThis[symbol]) throw new Error("signature_attempt_already_started");
    const value = { rejected: false, resolved: false };
    globalThis[symbol] = value;
    // REAL unchanged preload API. No cancellation or mocked native outcome.
    void window.api.updater.install().then(() => { value.resolved = true; }, () => { value.rejected = true; });
  }
  const value = globalThis[symbol];
  if (!value) throw new Error("signature_attempt_missing");
  return { rejected: value.rejected === true, resolved: value.resolved === true };
}

async function assertOriginalProcess(control) {
  const pids = await findOwnedPids(control.expected.executable);
  if (pids.length === 1 && pids[0] === control.expected.pid) return;
  // A replaced/extra app at the exact owned executable is never accepted.
  for (const pid of pids) await terminateOwned(control.expected.executable, pid);
  throw new VerificationFailure("failed", "signature_original_process_changed");
}

async function verifyNativeSignatureRejection(control, base, before, traffic) {
  const connection = await sidecar(control);
  await evaluate(control.main, probeExpression(control.expected, "arm"));
  try {
    await windowValue(control, `(${signaturePreloadAttempt.toString()})("start",${JSON.stringify(INSTALL_ATTEMPT)})`);
    const observed = await waitFor(async () => {
      await assertOriginalProcess(control);
      const native = await evaluate(control.main, probeExpression(control.expected, "read"));
      if (native.downloaded || native.beforeQuit) {
        for (const pid of await findOwnedPids(base.executable)) await terminateOwned(base.executable, pid);
        throw new VerificationFailure("failed", "signature_native_accepted");
      }
      const attempt = await windowValue(control, `(${signaturePreloadAttempt.toString()})("read",${JSON.stringify(INSTALL_ATTEMPT)})`);
      if (attempt.resolved) {
        for (const pid of await findOwnedPids(base.executable)) await terminateOwned(base.executable, pid);
        throw new VerificationFailure("failed", "signature_native_accepted");
      }
      return attempt.rejected || attempt.resolved ? { native, attempt } : false;
    }, { timeoutMs: 210000, intervalMs: 100, code: "signature_native_rejection_unverified" });
    await assertOriginalProcess(control);
    observed.native = await evaluate(control.main, probeExpression(control.expected, "read"));
    const baseAsar = await sha256File(path.resolve(base.executable, "../../Resources/app.asar")) === base.asarSha256;
    if (!baseAsar || observed.native.downloaded || observed.native.beforeQuit) {
      for (const pid of await findOwnedPids(base.executable)) await terminateOwned(base.executable, pid);
      throw new VerificationFailure("failed", "signature_native_accepted");
    }
    const currentConnection = await sidecar(control);
    const sidecarUnchanged = connection.url === currentConnection.url && connection.authorization === currentConnection.authorization;
    const outcome = signatureInstallOutcome({ ...observed, originalPid: true, baseAsar, sidecarUnchanged,
      completePayload: traffic.metadata > 0 && traffic.sent >= traffic.expectedBytes });
    console.log(JSON.stringify({ schemaVersion: 1, check: "signature_native_preflight", outcome,
      ...observed.native, preloadRejected: observed.attempt.rejected, originalPid: true, baseAsar, sidecarUnchanged }));
    check(outcome === "passed", `signature_native_rejection_${outcome}`, outcome === "failed" ? "failed" : "unverified");
    // Real saved-session read proves the original sidecar still serves data.
    await localRequest(connection, `/session/${before.session}`, before.project);
    await preserved(control, before);
  } finally {
    await evaluate(control.main, probeExpression(control.expected, "close")).catch(() => undefined);
  }
}

function quitOwnedBase(expected) {
  const require = process.getBuiltinModule("module").createRequire(process.resourcesPath + "/app.asar/package.json");
  const electron = require("electron");
  if (process.pid !== expected.pid || process.execPath !== expected.executable || process.resourcesPath !== expected.resources ||
    !electron.app.isPackaged || electron.app.getVersion() !== expected.version) throw new Error("owned_scope_required");
  // Schedule after this RPC can reply. The owned inspector must close before
  // normal quit, otherwise Node can wait for its diagnostic client to detach.
  setTimeout(() => {
    process.getBuiltinModule("inspector").close();
    electron.app.quit();
  }, 150);
  return true;
}

export function validatePreservation(before, after) {
  return before.marker === after.marker && before.store === after.store && before.session === after.session &&
    before.title === after.title && before.messages.length > 0 && before.messages.every((id) => after.messages.includes(id)) &&
    after.signedOut === true;
}

export function syntheticShellCommand(marker, project) {
  check(/^Public native update canary [a-f0-9-]{36}\n$/.test(marker), "synthetic_marker_invalid");
  check(typeof project === "string" && /^\/Users\/runner\/(?:[A-Za-z0-9_-]+\/)*public-native-update-[A-Za-z0-9]{6}\/synthetic-project$/.test(project),
    "synthetic_project_invalid");
  // Keep the command itself newline-free. The shell API's JSON-quoted eval
  // wrapper can turn embedded command LF into literal backslash+n; printf's
  // explicit format escape produces the exact expected LF without that case.
  return `/usr/bin/printf '%s\\n' '${marker.slice(0, -1)}' > '${project}/update-canary.txt'`;
}

export function shellSeedObservation(response, expected, actual) {
  check(/^Public native update canary [a-f0-9-]{36}\n$/.test(expected), "synthetic_marker_invalid");
  check(actual === undefined || typeof actual === "string" && Buffer.byteLength(actual) <= 4096, "shell_observation_invalid");
  const parts = Array.isArray(response?.parts) && response.parts.length <= 16 ? response.parts.filter((part) => part.type === "tool") : [];
  const state = parts.length === 1 ? parts[0].state : undefined;
  const exit = state?.metadata?.exit ?? state?.metadata?.exitCode;
  return { toolPartCount: parts.length, toolStatus: ["pending", "running", "completed", "error"].includes(state?.status) ? state.status : "unknown",
    exitCode: Number.isInteger(exit) && exit >= 0 && exit <= 255 ? exit : null,
    fileRead: typeof actual === "string", expectedBytes: Buffer.byteLength(expected), actualBytes: typeof actual === "string" ? Buffer.byteLength(actual) : null,
    digestMatches: typeof actual === "string" && createHash("sha256").update(actual).digest("hex") === createHash("sha256").update(expected).digest("hex"),
    actualEndsInLf: typeof actual === "string" && actual.endsWith("\n"),
    literalBackslashNMatches: typeof actual === "string" && actual === expected.slice(0, -1) + "\\n" };
}

export function nativeShellCommandFixture(project) {
  check(typeof project === "string" && /^\/Users\/runner\/(?:[A-Za-z0-9_-]+\/)*public-native-update-[A-Za-z0-9]{6}\/synthetic-project$/.test(project),
    "synthetic_project_invalid");
  const filename = `${project}/native-shell-command-canary.txt`;
  return { filename, expected: "Native shell command fixture\nliteral $(/usr/bin/printf MUST_STAY_LITERAL)\n",
    command: `/usr/bin/printf '%s\\n' 'Native shell command fixture' > '${filename}'\n/usr/bin/printf '%s\\n' 'literal $(/usr/bin/printf MUST_STAY_LITERAL)' >> '${filename}'` };
}

export function payloadChunk(chunk, scenario, alreadyChanged) {
  if (scenario !== "checksum" || alreadyChanged) return { bytes: chunk, corrupted: false };
  check(chunk.length > 0, "payload_chunk_invalid");
  const bytes = Buffer.from(chunk);
  bytes[0] ^= 1;
  return { bytes, corrupted: true };
}

export function caseReceipt({ scenario, arch, version, status, code, phase, sourceCommit, candidateZipSha256, baseZipSha256 }) {
  check(SCENARIOS.includes(scenario) && ["arm64", "x64"].includes(arch) && /^\d+\.\d+\.\d+$/.test(version) &&
    ["passed", "failed", "unverified"].includes(status) && (!code || /^[a-z][a-z0-9_]{0,63}$/.test(code)) &&
    (phase === undefined || PHASES.includes(phase)), "case_receipt_invalid");
  const identity = {};
  if (sourceCommit !== undefined || candidateZipSha256 !== undefined || baseZipSha256 !== undefined) {
    check(/^[a-f0-9]{40}$/.test(sourceCommit) && /^[a-f0-9]{64}$/.test(candidateZipSha256) &&
      /^[a-f0-9]{64}$/.test(baseZipSha256), "case_receipt_identity_invalid");
    Object.assign(identity, { sourceCommit, candidateZipSha256, baseZipSha256 });
  }
  return { schemaVersion: 1, flow: "update", scenario, arch, version, status, ...identity, ...(phase ? { phase } : {}),
    ...(code ? { code } : {}), preservationScope: "sidecar_shell_chat_and_preload_store_canary",
    editorDraftRestoration: "not_claimed", paidCoding: false, productionAccount: false, buildAttestation: false };
}

async function sha512File(filename) {
  const hash = createHash("sha512");
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest("base64");
}

async function makeFeed({ pins, arch, files }) {
  const artifacts = pins.artifacts[arch];
  const hashes = { good: await sha512File(files.zip), base: await sha512File(files.base),
    ...(files.negative ? { signature: await sha512File(files.negative) } : {}) };
  if (artifacts.zip.sha512) check(hashes.good === artifacts.zip.sha512, "feed_hash_pin_mismatch", "failed");
  const state = { scenario: "positive", traffic: undefined };
  const sockets = new Set();
  const server = createServer((request, response) => {
    const traffic = state.traffic;
    if (!traffic || request.socket.remoteAddress !== "127.0.0.1" ||
      request.headers.host !== `127.0.0.1:${server.address().port}` || !["GET", "HEAD"].includes(request.method)) {
      response.writeHead(403).end(); return;
    }
    const url = new URL(request.url, `http://127.0.0.1:${server.address().port}`);
    const relative = url.pathname.slice(1);
    if (relative === "latest-mac.yml") {
      traffic.metadata++;
      if (state.scenario === "offline") { request.socket.destroy(); return; }
      if (state.scenario === "unavailable") { response.writeHead(503).end(); return; }
      const bad = state.scenario === "signature";
      const artifact = bad ? artifacts.badSignatureZip : artifacts.zip;
      if (!artifact) { response.writeHead(503).end(); return; }
      const version = state.scenario === "baseline" ? pins.baseVersion : state.scenario === "downgrade" ?
        pins.baseVersion.replace(/\d+$/, (part) => String(Math.max(0, Number(part) - 1))) : pins.version;
      const body = metadata({ version, name: artifact.name, bytes: artifact.bytes, sha512: bad ? hashes.signature : hashes.good });
      response.writeHead(200, { "Content-Type": "text/yaml", "Content-Length": Buffer.byteLength(body), "Cache-Control": "no-store" });
      response.end(request.method === "HEAD" ? undefined : body); return;
    }
    if (relative === artifacts.zipBlockmap.name) {
      response.writeHead(200, { "Content-Length": artifacts.zipBlockmap.bytes });
      if (request.method === "HEAD") { response.end(); return; }
      createReadStream(files.blockmap).on("error", () => response.destroy()).pipe(response); return;
    }
    const bad = state.scenario === "signature";
    const artifact = bad ? artifacts.badSignatureZip : artifacts.zip;
    if (!artifact || relative !== artifact.name) { response.writeHead(404).end(); return; }
    traffic.zip++;
    if (traffic.zip > 24) { response.writeHead(503).end(); return; }
    const selected = byteRange(request.headers.range, artifact.bytes);
    if (!selected) { response.writeHead(416, { "Content-Range": `bytes */${artifact.bytes}` }).end(); return; }
    response.writeHead(selected.partial ? 206 : 200, { "Content-Type": "application/zip", "Accept-Ranges": "bytes",
      "Content-Length": selected.length,
      ...(selected.partial ? { "Content-Range": `bytes ${selected.start}-${selected.end}/${artifact.bytes}` } : {}) });
    if (request.method === "HEAD") { response.end(); return; }
    const stream = createReadStream(bad ? files.negative : files.zip, { start: selected.start, end: selected.end, highWaterMark: 65536 });
    let altered = false;
    let interrupted = false;
    stream.on("data", (chunk) => {
      if (interrupted) return;
      const changed = payloadChunk(chunk, state.scenario, altered);
      const bytes = changed.bytes;
      if (changed.corrupted) { altered = true; traffic.corrupted++; }
      traffic.sent += bytes.length;
      if (!response.write(bytes)) { stream.pause(); response.once("drain", () => stream.resume()); }
      if (state.scenario === "interrupted") {
        interrupted = true; traffic.interrupted++; stream.destroy();
        setTimeout(() => response.destroy(), 50).unref();
      }
    });
    stream.on("end", () => { if (!interrupted) response.end(); });
    stream.on("error", () => response.destroy());
    response.on("close", () => stream.destroy());
  });
  server.on("connection", (socket) => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return {
    url: `http://127.0.0.1:${server.address().port}/`,
    select(scenario) {
      state.scenario = scenario;
      state.traffic = { metadata: 0, zip: 0, sent: 0, corrupted: 0, interrupted: 0,
        expectedBytes: (scenario === "signature" ? artifacts.badSignatureZip : artifacts.zip)?.bytes ?? 0 };
      return state.traffic;
    },
    close: () => new Promise((resolve) => { for (const socket of sockets) socket.destroy(); server.close(resolve); }),
  };
}

function applicationEnvironment() {
  const allowed = ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "DISPLAY", "__CF_USER_TEXT_ENCODING"];
  return Object.fromEntries(allowed.filter((key) => typeof process.env[key] === "string").map((key) => [key, process.env[key]]));
}

function mainExpression(fn, expected, data) {
  return `(${fn.toString()})(${JSON.stringify(expected)},${JSON.stringify(data)})`;
}

function attestMain(expected) {
  const require = process.getBuiltinModule("module").createRequire(process.resourcesPath + "/app.asar/package.json");
  const electron = require("electron");
  return process.pid === expected.pid && process.execPath === expected.executable && process.arch === expected.arch &&
    process.resourcesPath === expected.resources && electron.app.isPackaged && electron.app.getVersion() === expected.version;
}

async function inWindow(expected, expression) {
  const require = process.getBuiltinModule("module").createRequire(process.resourcesPath + "/app.asar/package.json");
  const electron = require("electron");
  if (process.pid !== expected.pid || process.execPath !== expected.executable || process.resourcesPath !== expected.resources ||
    !electron.app.isPackaged || electron.app.getVersion() !== expected.version) throw new Error("owned_scope_required");
  const windows = electron.BrowserWindow.getAllWindows().filter((window) => !window.isDestroyed() && window.isVisible() &&
    !window.webContents.isDestroyed() && window.webContents.getURL().startsWith("program-ai://renderer/"));
  if (windows.length !== 1) throw new Error("owned_renderer_required");
  return windows[0].webContents.executeJavaScript(expression, true);
}

function changeFeed(expected, value) {
  const url = new URL(value);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || !url.port || url.username || url.password || url.hash) throw new Error("loopback_required");
  const require = process.getBuiltinModule("module").createRequire(process.resourcesPath + "/app.asar/package.json");
  const electron = require("electron");
  if (process.pid !== expected.pid || process.execPath !== expected.executable || !electron.app.isPackaged ||
    electron.app.getVersion() !== expected.version) throw new Error("owned_scope_required");
  require("electron-updater").autoUpdater.setFeedURL({ provider: "generic", url: url.href });
  return true;
}

export function pausedCallFrame(event) {
  const id = event?.callFrames?.[0]?.callFrameId;
  return typeof id === "string" && id.length > 0 && id.length <= 1024 && !/[\u0000-\u001f\u007f]/.test(id) ? id : undefined;
}

export async function evaluatePaused(main, callFrameId, expression) {
  check(pausedCallFrame({ callFrames: [{ callFrameId }] }), "paused_frame_unverified");
  // CDP defines this synchronous command for a paused call frame. Runtime's
  // awaitPromise evaluation is not used before the owned VM resumes.
  const result = await main.send("Debugger.evaluateOnCallFrame", {
    callFrameId, expression, returnByValue: true, silent: true,
  }, 20000);
  check(!result?.exceptionDetails && result?.result?.type === "boolean" && result.result.value === true,
    "paused_evaluation_unverified");
  return true;
}

export async function bootstrapMain(main, expected, feedUrl, observePhase) {
  let frame;
  const stop = main.onEvent("Debugger.paused", (event) => { frame = pausedCallFrame(event); });
  try {
    observePhase("base_debugger_enable");
    await main.send("Debugger.enable");
    observePhase("base_waiting_release");
    await main.send("Runtime.runIfWaitingForDebugger");
    observePhase("base_pause_wait");
    const callFrameId = await waitFor(() => frame, { timeoutMs: 10000, code: "signed_base_diagnostic_pause_unavailable" });
    observePhase("base_attest");
    await evaluatePaused(main, callFrameId, mainExpression(attestMain, expected));
    // The shipping app starts its updater during startup. Override this owned
    // singleton before resuming any app code, initially offering only N itself.
    observePhase("base_feed");
    await evaluatePaused(main, callFrameId, mainExpression(changeFeed, expected, feedUrl));
    observePhase("base_debugger_resume");
    await main.send("Debugger.resume");
    observePhase("base_debugger_disable");
    await main.send("Debugger.disable");
  } finally { stop(); }
}

export function childExitObservation(value) {
  const signals = ["SIGABRT", "SIGBUS", "SIGSEGV", "SIGILL", "SIGTRAP", "SIGKILL", "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"];
  const signal = value.signalCode ?? (value.signal === "none" ? null : value.signal);
  return { exitObserved: value.exitObserved === true || value.exitCode != null || signal != null,
    closeObserved: value.closeObserved === true, spawnError: value.spawnError === true,
    exitCode: Number.isInteger(value.exitCode) && value.exitCode >= 0 && value.exitCode <= 255 ? value.exitCode : null,
    signal: signal == null ? "none" : signals.includes(signal) ? signal : "other" };
}

export function observeChildExit(child) {
  let exitObserved = false, closeObserved = false, spawnError = false, exitCode = null, signalCode = null;
  child.on("exit", (code, signal) => { exitObserved = true; exitCode = code; signalCode = signal; });
  child.on("close", () => { closeObserved = true; });
  child.on("error", () => { spawnError = true; });
  return { read: () => childExitObservation({ exitObserved, closeObserved, spawnError,
    exitCode: child.exitCode ?? exitCode, signalCode: child.signalCode ?? signalCode }) };
}

export function nativeStageObservation(value = {}) {
  const result = {};
  for (const name of ["checking", "available", "downloaded", "notAvailable", "errors", "beforeQuitForUpdate", "appBeforeQuit", "appWillQuit", "appQuit"])
    result[name] = Number.isInteger(value[name]) && value[name] >= 0 ? Math.min(16, value[name]) : 0;
  const codes = { signature: [-1, -2], updater: [2, 3, 4, 5, 6, 7, 8], installer: [-1, -2, -3, -4, -5, -6, -7, -8, -9], shipit_request: [1, 2, 3], shipit_launcher: [1] };
  const domain = Object.hasOwn(codes, value.errorDomain) ? value.errorDomain : value.errorDomain === "none" || value.errorDomain == null && result.errors === 0 ? "none" : "other";
  return { ...result, saturated: value.saturated === true, errorDomain: domain,
    errorCode: codes[domain]?.includes(value.errorCode) ? value.errorCode : null };
}

// Read-only event listeners. No checks/quit calls, event injection, cancellation,
// or listener removals. Publish only counters and strict primary error enums.
export function createNativeHandoffObserver(native, app, publish) {
  const state = { checking: 0, available: 0, downloaded: 0, notAvailable: 0, errors: 0,
    beforeQuitForUpdate: 0, appBeforeQuit: 0, appWillQuit: 0, appQuit: 0, saturated: false, errorDomain: "none", errorCode: null };
  let published = 0;
  const send = () => { if (published >= 128) return; published++; try { publish({ ...state }); } catch {} };
  const bump = (name) => { if (state[name] === 16) state.saturated = true; else state[name]++; send(); };
  for (const [event, name] of [["checking-for-update", "checking"], ["update-available", "available"], ["update-downloaded", "downloaded"],
    ["update-not-available", "notAvailable"], ["before-quit-for-update", "beforeQuitForUpdate"]]) native.on(event, () => bump(name));
  // Do not turn an otherwise-unhandled EventEmitter error into a handled one.
  // The shipping SDK normally owns a persistent error listener already.
  if (native.listenerCount("error") > 0) native.on("error", (error) => {
    const domains = { SQRLCodeSignatureErrorDomain: ["signature", [-1, -2]], SQRLUpdaterErrorDomain: ["updater", [2, 3, 4, 5, 6, 7, 8]],
      SQRLInstallerErrorDomain: ["installer", [-1, -2, -3, -4, -5, -6, -7, -8, -9]], SQRLShipItRequestErrorDomain: ["shipit_request", [1, 2, 3]], SQRLShipItLauncherErrorDomain: ["shipit_launcher", [1]] };
    const known = Object.hasOwn(domains, error?.domain) ? domains[error.domain] : undefined;
    state.errorDomain = known ? known[0] : "other";
    state.errorCode = known?.[1].includes(error?.code) ? error.code : null;
    bump("errors");
  });
  for (const [event, name] of [["before-quit", "appBeforeQuit"], ["will-quit", "appWillQuit"], ["quit", "appQuit"]]) app.on(event, () => bump(name));
  send();
  return { read: () => ({ ...state }) };
}

export function createNativeStageCollector(marker) {
  check(/^PAI_HANDOFF_[a-f0-9-]{36} $/.test(marker), "native_marker_invalid");
  let line = "", dropping = false, armed = false, frames = 0, last = nativeStageObservation();
  return {
    push(chunk) {
      // Never retain ordinary stderr. Only a short exact-prefix frame can be
      // buffered; oversized lines are discarded through the next newline.
      const text = String(chunk).slice(-65536);
      for (const character of text) {
        if (dropping) { if (character === "\n") dropping = false; continue; }
        if (character === "\n") {
          if (line.startsWith(marker) && line.length <= marker.length + 1024) {
            try { last = nativeStageObservation(JSON.parse(line.slice(marker.length))); armed = true; frames = Math.min(128, frames + 1); } catch {}
          }
          line = ""; continue;
        }
        line += character;
        if (line.length <= marker.length ? !marker.startsWith(line) : line.length > marker.length + 1024) { line = ""; dropping = true; }
      }
    },
    read: () => ({ armed, frames, ...last }),
  };
}

function armNativeStage(expected, data, factory) {
  const require = process.getBuiltinModule("module").createRequire(process.resourcesPath + "/app.asar/package.json");
  const electron = require("electron");
  if (process.pid !== expected.pid || process.execPath !== expected.executable || process.resourcesPath !== expected.resources ||
    !electron.app.isPackaged || electron.app.getVersion() !== expected.version || !/^PAI_HANDOFF_[a-f0-9-]{36} $/.test(data.marker)) throw new Error("owned_scope_required");
  const key = Symbol.for("program-ai-public-native-stage-observer");
  if (globalThis[key]) return true;
  globalThis[key] = factory(electron.autoUpdater, electron.app, (value) => {
    try { process.stderr.write(data.marker + JSON.stringify(value) + "\n"); } catch {}
  });
  return true;
}

async function startBase(base, arch, version, feedUrl, observePhase) {
  const port = await unusedPort();
  const rendererPort = await unusedPort();
  const marker = `PAI_HANDOFF_${randomUUID()} `;
  const nativeStage = createNativeStageCollector(marker);
  observePhase("base_spawn");
  const child = spawn(base.executable, [`--inspect-brk=127.0.0.1:${port}`, `--remote-debugging-port=${rendererPort}`, "--remote-debugging-address=127.0.0.1"], {
    env: applicationEnvironment(), stdio: ["ignore", "ignore", "pipe"],
  });
  const childExit = observeChildExit(child);
  child.stderr.on("data", (chunk) => nativeStage.push(chunk)); // Non-coded app stderr is discarded.
  check(Number.isSafeInteger(child.pid) && child.pid > 1, "owned_spawn_unverified");
  observePhase("base_diagnostic_connect");
  const main = await connectCdp(port, child.pid, { targetType: "node", executable: base.executable, timeoutMs: 30000 });
  const expected = { pid: child.pid, executable: base.executable, resources: path.resolve(base.executable, "../../Resources"), arch, version };
  try { await bootstrapMain(main, expected, feedUrl, observePhase); }
  catch (error) { main.close(); throw error; }
  // Diagnostic failure never changes a native verification/pass gate.
  await evaluate(main, `(${armNativeStage.toString()})(${JSON.stringify(expected)},${JSON.stringify({ marker })},(${createNativeHandoffObserver.toString()}))`).catch(() => undefined);
  return { main, expected, child, rendererPort, handoff: { childExit, nativeStage } };
}

async function windowValue(control, expression, timeoutMs = 30000) {
  return evaluate(control.main, mainExpression(inWindow, control.expected, expression), timeoutMs);
}

async function ready(control) {
  return waitFor(async () => {
    const value = await windowValue(control, `(async()=>{const a=window.api;if(!a?.awaitInitialization||!a?.updater?.check||!a?.updater?.install||!a?.storeSet||!a?.storeGet||!a?.programAICloudAuth?.getState)return false;return (await a.programAICloudAuth.getState()).status==='signed_out'&&document.body.innerText.trim().length>20})()`);
    return value === true;
  }, { timeoutMs: 90000, code: "signed_out_preload_unavailable" });
}

export async function rendererReadySnapshot(api, document) {
  const preload = { awaitInitialization: typeof api?.awaitInitialization === "function", updaterCheck: typeof api?.updater?.check === "function",
    updaterInstall: typeof api?.updater?.install === "function", storeSet: typeof api?.storeSet === "function",
    storeGet: typeof api?.storeGet === "function", authGetState: typeof api?.programAICloudAuth?.getState === "function" };
  const result = { apiPresent: api !== null && typeof api === "object", preload, documentMeaningful: typeof document?.body?.innerText === "string" && document.body.innerText.trim().length > 20,
    authStatus: "unknown", authReason: "function_missing" };
  if (!preload.authGetState) return result;
  let timer;
  try {
    const observed = await Promise.race([
      Promise.resolve().then(() => api.programAICloudAuth.getState()).then((state) => ({ kind: "state", state }), () => ({ kind: "rejected" })),
      new Promise((resolve) => { timer = setTimeout(() => resolve({ kind: "timeout" }), 2000); }),
    ]);
    if (observed.kind !== "state") return { ...result, authReason: observed.kind === "timeout" ? "timeout" : "request_failed" };
    const state = observed.state;
    const authStatus = ["signed_out", "signed_in", "unavailable", "error"].includes(state?.status) ? state.status :
      ["signing_in", "authenticating"].includes(state?.status) ? "authenticating" : "unknown";
    const authReason = authStatus === "unavailable" ? ["configuration", "secure_storage"].includes(state.reason) ? state.reason : "unknown" :
      authStatus === "error" ? "auth_error" : authStatus === "unknown" ? "unknown" : "none";
    return { ...result, authStatus, authReason };
  } finally { clearTimeout(timer); }
}

export function readyPhaseObservation(value = {}) {
  const count = (name) => Number.isInteger(value[name]) && value[name] >= 0 ? Math.min(16, value[name]) : 0;
  const preload = {};
  for (const name of ["awaitInitialization", "updaterCheck", "updaterInstall", "storeSet", "storeGet", "authGetState"]) preload[name] = value.preload?.[name] === true;
  return { diagnosticStatus: value.mainAttested === true ? "observed" : "unavailable", mainAttested: value.mainAttested === true,
    allWindowCount: count("allWindowCount"), visibleWindowCount: count("visibleWindowCount"),
    programRendererWindowCount: count("programRendererWindowCount"), visibleProgramRendererCount: count("visibleProgramRendererCount"),
    windowCountsSaturated: value.windowCountsSaturated === true, rendererChecked: value.rendererChecked === true, apiPresent: value.apiPresent === true, preload,
    documentMeaningful: value.documentMeaningful === true,
    authStatus: ["signed_out", "signed_in", "unavailable", "authenticating", "error", "unknown"].includes(value.authStatus) ? value.authStatus : "unknown",
    authReason: ["none", "configuration", "secure_storage", "auth_error", "unknown", "function_missing", "timeout", "request_failed"].includes(value.authReason) ? value.authReason : "unknown" };
}

async function mainReadySnapshot(expected, rendererSnapshot) {
  const require = process.getBuiltinModule("module").createRequire(process.resourcesPath + "/app.asar/package.json");
  const electron = require("electron");
  if (process.pid !== expected.pid || process.execPath !== expected.executable || process.resourcesPath !== expected.resources ||
    !electron.app.isPackaged || electron.app.getVersion() !== expected.version) throw new Error("owned_scope_required");
  const all = electron.BrowserWindow.getAllWindows();
  const visible = all.filter((window) => !window.isDestroyed() && window.isVisible());
  const program = all.filter((window) => !window.isDestroyed() && !window.webContents.isDestroyed() && window.webContents.getURL().startsWith("program-ai://renderer/"));
  const selected = program.filter((window) => window.isVisible());
  const counts = { mainAttested: true, allWindowCount: Math.min(16, all.length), visibleWindowCount: Math.min(16, visible.length),
    programRendererWindowCount: Math.min(16, program.length), visibleProgramRendererCount: Math.min(16, selected.length),
    windowCountsSaturated: [all, visible, program, selected].some((windows) => windows.length > 16), rendererChecked: false };
  if (selected.length !== 1) return counts;
  try { return { ...counts, ...await selected[0].webContents.executeJavaScript(`(${rendererSnapshot.toString()})(window.api,document)`, true), rendererChecked: true }; }
  catch { return counts; }
}

async function reportReadyFailure(control) {
  let value;
  try { value = await evaluate(control.main, `(${mainReadySnapshot.toString()})(${JSON.stringify(control.expected)},(${rendererReadySnapshot.toString()}))`, 5000); }
  catch { value = {}; }
  console.log(JSON.stringify({ schemaVersion: 1, check: "ready_phase_diagnostics", ...readyPhaseObservation(value) }));
}

async function sidecar(control) {
  const connection = await windowValue(control, "window.api.awaitInitialization()", 90000);
  const url = loopbackUrl(connection?.url);
  check(url.pathname === "/" && !url.search && typeof connection.username === "string" && typeof connection.password === "string", "sidecar_contract_unverified");
  return { url: url.origin, authorization: `Basic ${Buffer.from(connection.username + ":" + connection.password).toString("base64")}` };
}

async function localRequest(connection, route, directory, body) {
  check(/^\/session(?:\/[A-Za-z0-9_-]+(?:\/(?:shell|message))?)?$/.test(route), "sidecar_route_invalid");
  const url = new URL(route, connection.url);
  url.searchParams.set("directory", directory);
  const response = await fetch(url, { method: body ? "POST" : "GET", redirect: "error", signal: AbortSignal.timeout(120000),
    headers: { Authorization: connection.authorization, ...(body ? { "Content-Type": "application/json" } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}) });
  check(response.ok, "sidecar_operation_unverified");
  const text = await response.text();
  check(text.length < 2 * 1024 * 1024, "sidecar_response_limit");
  try { return JSON.parse(text); } catch { throw new VerificationFailure("unverified", "sidecar_response_invalid"); }
}

function messageIds(value) {
  check(Array.isArray(value), "saved_messages_unverified");
  const ids = value.map((item) => item.info?.id ?? item.id).filter((id) => typeof id === "string" && /^[A-Za-z0-9_-]{8,128}$/.test(id));
  check(ids.length > 0, "saved_messages_unverified");
  return ids;
}

async function seed(control, root) {
  const project = path.join(root, "synthetic-project");
  await mkdir(project, { mode: 0o700 });
  const marker = `Public native update canary ${randomUUID()}\n`;
  const title = "Public signed-update shell chat";
  const connection = await sidecar(control);
  const session = await localRequest(connection, "/session", project, { title });
  check(typeof session.id === "string" && /^[A-Za-z0-9_-]{8,128}$/.test(session.id), "saved_session_unverified");
  const response = await localRequest(connection, `/session/${session.id}/shell`, project,
    { agent: "build", command: syntheticShellCommand(marker, project) });
  const messages = messageIds(await localRequest(connection, `/session/${session.id}/message`, project));
  const markerPath = path.join(project, "update-canary.txt");
  const info = await stat(markerPath).catch(() => undefined);
  const actual = info?.isFile() && info.size <= 4096 ? await readFile(markerPath, "utf8") : undefined;
  const observed = shellSeedObservation(response, marker, actual);
  console.log(JSON.stringify({ schemaVersion: 1, check: "shell_seed", ...observed }));
  check(observed.toolStatus === "completed" && observed.digestMatches && (observed.exitCode === null || observed.exitCode === 0), "shell_marker_unverified");
  const store = JSON.stringify({ text: "Synthetic unsent canary; not an editor-draft claim", session: session.id, marker });
  await windowValue(control, `window.api.storeSet('public-native-verification.dat','unsent-canary',${JSON.stringify(store)})`);
  return { project, marker, title, session: session.id, messages, store, signedOut: true };
}

async function preserved(control, before) {
  const connection = await sidecar(control);
  const session = await localRequest(connection, `/session/${before.session}`, before.project);
  const after = { marker: await readFile(path.join(before.project, "update-canary.txt"), "utf8"),
    store: await windowValue(control, "window.api.storeGet('public-native-verification.dat','unsent-canary')"),
    session: session.id, title: session.title,
    messages: messageIds(await localRequest(connection, `/session/${before.session}/message`, before.project)),
    signedOut: await windowValue(control, "window.api.programAICloudAuth.getState().then(s=>s.status==='signed_out')") };
  check(validatePreservation(before, after), "synthetic_state_not_preserved", "failed");
}

async function nativeShellCommandRegression(control, before) {
  const fixture = nativeShellCommandFixture(before.project);
  check(!(await stat(fixture.filename).catch(() => undefined)), "native_shell_fixture_preexisting");
  const connection = await sidecar(control);
  const response = await localRequest(connection, `/session/${before.session}/shell`, before.project, { agent: "build", command: fixture.command });
  const parts = Array.isArray(response?.parts) ? response.parts.filter((part) => part.type === "tool") : [];
  const status = parts.length === 1 && ["pending", "running", "completed", "error"].includes(parts[0].state?.status) ? parts[0].state.status : "unknown";
  const info = await stat(fixture.filename).catch(() => undefined);
  const bytes = info?.isFile() && info.size <= 4096 ? await readFile(fixture.filename) : undefined;
  const matches = !!bytes && bytes.equals(Buffer.from(fixture.expected));
  console.log(JSON.stringify({ schemaVersion: 1, check: "native_shell_command", toolStatus: status,
    fileRead: !!bytes, expectedBytes: Buffer.byteLength(fixture.expected), actualBytes: bytes?.length ?? null, byteMatch: matches,
    paidCoding: false, editorDraftRestoration: "not_claimed", queueDrain: "not_claimed" }));
  check(status === "completed" && matches, "native_shell_command_unverified");
}

async function checkUpdate(control) {
  return windowValue(control, `(async()=>(${updaterObservation.toString()})(await window.api.updater.check()))()`, 300000);
}

async function verifyNegativeFixture(app, candidate, pins, arch) {
  const result = await run("/usr/bin/plutil", ["-convert", "json", "-o", "-", path.join(app, "Contents/Info.plist")]);
  const info = JSON.parse(result.stdout);
  check(info.CFBundleIdentifier === pins.bundleId && info.CFBundleShortVersionString === pins.version &&
    info.CFBundleExecutable === "Program AI Desktop", "signature_fixture_identity_invalid");
  check(await sha256File(path.join(app, "Contents/Resources/app.asar")) === candidate.asarSha256,
    "signature_fixture_code_changed");
  const architecture = await run("/usr/bin/lipo", ["-archs", path.join(app, "Contents/MacOS", info.CFBundleExecutable)]);
  check(architecture.stdout.trim() === (arch === "x64" ? "x86_64" : "arm64"), "signature_fixture_arch_invalid");
  const description = await run("/usr/bin/codesign", ["-dvvv", app], { allowFailure: true });
  const signature = description.stdout + description.stderr;
  check(description.exitCode === 0 && /flags=.*\badhoc\b/.test(signature) &&
    !signature.includes(`TeamIdentifier=${pins.teamId}\n`), "signature_fixture_not_ad_hoc");
  await run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app], { code: "signature_fixture_malformed" });
}

async function setFeed(control, url) {
  loopbackUrl(url);
  check(await evaluate(control.main, mainExpression(changeFeed, control.expected, url)), "owned_feed_override_unverified");
}

export function createInstallPromiseObserver(invoke) {
  let outcome = "pending", errorClass = "none";
  const rejected = (error) => {
    const message = (error instanceof Error ? error.message : typeof error === "string" ? error : "").slice(0, 2048);
    errorClass = /signature|code.?sign|publisher|SQRLCodeSignatureErrorDomain/i.test(message) ? "signature" :
      /not ready/i.test(message) ? "not_ready" : /EACCES|EPERM|permission denied/i.test(message) ? "permission" :
      /network|socket|connect|download|http|offline|timeout/i.test(message) ? "network" : "other";
    outcome = "rejected";
  };
  return {
    start() { try { void invoke().then(() => { outcome = "resolved"; }, rejected); } catch (error) { rejected(error); } },
    read: () => ({ outcome, errorClass }),
  };
}

function replacementPreloadProbe(action, key, factory) {
  if (location.protocol !== "program-ai:" || location.hostname !== "renderer" || typeof window.api?.updater?.install !== "function")
    throw new Error("owned_renderer_required");
  const symbol = Symbol.for(key);
  if (action === "schedule") {
    if (globalThis[symbol]) throw new Error("install_observer_already_scheduled");
    const observer = factory(() => window.api.updater.install());
    globalThis[symbol] = observer;
    setTimeout(() => observer.start(), 1500); // Same real preload request and original delay.
  }
  if (!["schedule", "read"].includes(action) || !globalThis[symbol]) throw new Error("install_observer_missing");
  return globalThis[symbol].read();
}

function replacementProbeExpression(action) {
  return `(${replacementPreloadProbe.toString()})(${JSON.stringify(action)},"program-ai-public-replacement-install-observer",(${createInstallPromiseObserver.toString()}))`;
}

export function installPromiseObservation(value) {
  check(value && ["pending", "resolved", "rejected"].includes(value.outcome) &&
    ["none", "signature", "not_ready", "permission", "network", "other"].includes(value.errorClass) &&
    (value.outcome === "rejected" ? value.errorClass !== "none" : value.errorClass === "none"), "install_observation_invalid");
  return { outcome: value.outcome, errorClass: value.errorClass };
}

const SHIPIT_CACHE = "/Users/runner/Library/Caches/com.programai.desktop.ShipIt";
const SHIPIT_FILES = Object.freeze({ stderr: "ShipIt_stderr.log", stdout: "ShipIt_stdout.log", state: "ShipItState.plist" });
const SHIPIT_TAIL_BYTES = 65536;
const SHIPIT_FILE_LIMIT = 8 * 1024 * 1024;
const SHIPIT_READ_STATUSES = ["observed", "absent", "unchanged", "unsafe", "baseline_unavailable", "replaced", "truncated", "size_limit", "unavailable"];
// Squirrel source pinned by Electron42: 0e5d146b, Squirrel/ShipIt-main.m.
const SHIPIT_LOG_MARKERS = Object.freeze({ installRequestMarker: "Detected this as an install request",
  installationBeginMarker: "Beginning installation", installationResumeMarker: "Resuming installation attempt ",
  installationCompletedMarker: "Installation completed successfully", attemptsExhaustedMarker: "Too many attempts to install, aborting update",
  installationErrorMarker: "Installation error:", launchRequestMarker: "Detected this as a launch request",
  launchFailureMarker: "Could not launch application at ", launchSuccessMarker: "Successfully launched application at ",
  missingTargetMarker: "Missing target bundle URL, cannot launch application", newShipItExitedMarker: "New ShipIt exited", quitMarker: "ShipIt quitting" });

// Pure metadata policy. Logs count only bytes appended after the pre-install
// offset, never old content in a cache that this harness did not prove absent.
export function shipItReadPlan(before, after, state = false) {
  const refuse = (status) => ({ status, start: 0, length: 0, tailTruncated: false });
  if (!["absent", "owned"].includes(before?.status)) return refuse("baseline_unavailable");
  if (after?.status !== "owned") return refuse(after?.status === "absent" ? "absent" : "unsafe");
  if (!Number.isSafeInteger(after.size) || after.size < 0 || after.size > (state ? SHIPIT_TAIL_BYTES : SHIPIT_FILE_LIMIT)) return refuse("size_limit");
  if (state) {
    if (before.status === "owned" && before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs) return refuse("unchanged");
    return { status: "observed", start: 0, length: after.size, tailTruncated: false };
  }
  if (before.status === "owned" && (before.dev !== after.dev || before.ino !== after.ino)) return refuse("replaced");
  const offset = before.status === "owned" ? before.size : 0;
  if (!Number.isSafeInteger(offset) || offset < 0 || after.size < offset) return refuse("truncated");
  if (after.size === offset) return refuse("unchanged");
  const start = Math.max(offset, after.size - SHIPIT_TAIL_BYTES);
  return { status: "observed", start, length: after.size - start, tailTruncated: start > offset };
}

export function shipItStateObservation(text, target) {
  const result = { jsonValid: false, targetMatches: false, bundleMatches: false, localUpdate: false,
    launchAfterInstallation: false, useUpdateBundleName: false };
  if (typeof text !== "string" || Buffer.byteLength(text) > SHIPIT_TAIL_BYTES) return result;
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) return result;
    result.jsonValid = true;
    const local = (raw) => { const url = new URL(raw); return url.protocol === "file:" && !url.hostname && !url.username && !url.password && !url.port && !url.search && !url.hash ? fileURLToPath(url) : undefined; };
    result.targetMatches = typeof value.targetBundleURL === "string" && local(value.targetBundleURL) === target;
    result.bundleMatches = value.bundleIdentifier === "com.programai.desktop";
    result.localUpdate = typeof value.updateBundleURL === "string" && typeof local(value.updateBundleURL) === "string";
    result.launchAfterInstallation = value.launchAfterInstallation === true;
    result.useUpdateBundleName = value.useUpdateBundleName === true;
  } catch {}
  return result;
}

export function shipItLogObservation(texts) {
  // Fixed primary-source strings only. These are diagnostic markers, not
  // installer success/pass gates. Unknown text is never printed or guessed.
  const source = (Array.isArray(texts) ? texts.slice(0, 2) : []).map((text) =>
    typeof text === "string" ? Buffer.from(text).subarray(-SHIPIT_TAIL_BYTES).toString("utf8") : "").join("\n");
  const installerCodes = [...new Set([...source.matchAll(/\bSQRLInstallerErrorDomain\s+(?:Code=|error\s+)(-[1-9])\b/g)].map((match) => Number(match[1])))].sort((a, b) => a - b);
  const result = { installerCodes, installerDomainSeen: source.includes("SQRLInstallerErrorDomain"),
    signatureDomainSeen: source.includes("SQRLCodeSignatureErrorDomain"), requestReadError: source.includes("Could not read update request"),
    requestWriteError: source.includes("Could not write update request"), bundleMoveStarted: source.includes("Moving bundle from "),
    bundleMoveCompleted: source.includes("Moved bundle contents from "), rollbackError: source.includes("Couldn't abort install and restore owned bundle") };
  for (const [name, marker] of Object.entries(SHIPIT_LOG_MARKERS)) result[name] = source.includes(marker);
  return { ...result, unknownTextSeen: source.trim().length > 0 && installerCodes.length === 0 && !Object.values(result).some((value) => value === true) };
}

export function shipItDiagnosticObservation(value = {}) {
  const files = {};
  for (const kind of Object.keys(SHIPIT_FILES)) files[kind] = { status: SHIPIT_READ_STATUSES.includes(value.files?.[kind]?.status) ? value.files[kind].status : "unavailable", tailTruncated: value.files?.[kind]?.tailTruncated === true };
  const logs = { installerCodes: Array.isArray(value.logs?.installerCodes) ? [...new Set(value.logs.installerCodes.filter((code) => Number.isInteger(code) && code >= -9 && code <= -1))].sort((a, b) => a - b) : [] };
  for (const name of ["installerDomainSeen", "signatureDomainSeen", "requestReadError", "requestWriteError", "bundleMoveStarted", "bundleMoveCompleted", "rollbackError", "unknownTextSeen", ...Object.keys(SHIPIT_LOG_MARKERS)]) logs[name] = value.logs?.[name] === true;
  const state = {};
  for (const name of ["jsonValid", "targetMatches", "bundleMatches", "localUpdate", "launchAfterInstallation", "useUpdateBundleName"]) state[name] = value.state?.[name] === true;
  return { baselineRecorded: value.baselineRecorded === true, cacheWasAbsent: value.cacheWasAbsent === true, cacheOwned: value.cacheOwned === true, cacheAbsent: value.cacheAbsent === true, files, logs, state };
}

async function shipItCacheOwned() {
  try {
    const info = await lstat(SHIPIT_CACHE);
    return info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid() && await realpath(SHIPIT_CACHE) === SHIPIT_CACHE ? "owned" : "unsafe";
  } catch (error) { return error.code === "ENOENT" ? "absent" : "unsafe"; }
}

async function shipItMetadata(name) {
  try {
    const info = await lstat(path.join(SHIPIT_CACHE, name));
    if (!info.isFile() || info.isSymbolicLink() || info.uid !== process.getuid()) return { status: "unsafe" };
    return { status: "owned", dev: info.dev, ino: info.ino, size: info.size, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs };
  } catch (error) { return { status: error.code === "ENOENT" ? "absent" : "unsafe" }; }
}

async function captureShipItBaseline(base) {
  const cache = await shipItCacheOwned();
  const files = {};
  for (const [kind, name] of Object.entries(SHIPIT_FILES)) files[kind] = cache === "owned" ? await shipItMetadata(name) : { status: cache };
  return { cache, files, target: path.resolve(base.executable, "../../..") };
}

async function readShipItFile(kind, baseline) {
  const name = SHIPIT_FILES[kind];
  if (!name || !baseline) return { status: "baseline_unavailable", tailTruncated: false };
  const cache = await shipItCacheOwned();
  if (cache !== "owned") return { status: cache === "absent" ? "absent" : "unsafe", tailTruncated: false };
  const metadata = await shipItMetadata(name);
  const plan = shipItReadPlan(baseline.files[kind], metadata, kind === "state");
  if (plan.status !== "observed") return { status: plan.status, tailTruncated: false };
  let handle;
  try {
    // Read-only, no symlink traversal, and re-check the same opened inode.
    handle = await open(path.join(SHIPIT_CACHE, name), constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await handle.stat();
    if (!info.isFile() || info.uid !== process.getuid() || info.dev !== metadata.dev || info.ino !== metadata.ino || info.size < metadata.size) return { status: "unsafe", tailTruncated: false };
    const bytes = Buffer.alloc(plan.length);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, plan.start);
    if (bytesRead !== plan.length) return { status: "unavailable", tailTruncated: false };
    return { status: "observed", tailTruncated: plan.tailTruncated, text: bytes.toString("utf8") };
  } catch { return { status: "unavailable", tailTruncated: false }; }
  finally { await handle?.close().catch(() => undefined); }
}

async function readShipItDiagnostics(baseline) {
  if (!baseline) return shipItDiagnosticObservation();
  const files = {};
  for (const kind of Object.keys(SHIPIT_FILES)) files[kind] = await readShipItFile(kind, baseline);
  const cache = await shipItCacheOwned();
  return { baselineRecorded: !!baseline, cacheWasAbsent: baseline?.cache === "absent", cacheOwned: cache === "owned", cacheAbsent: cache === "absent",
    files: Object.fromEntries(Object.entries(files).map(([kind, value]) => [kind, { status: value.status, tailTruncated: value.tailTruncated }])),
    logs: shipItLogObservation([files.stderr.text ?? "", files.stdout.text ?? ""]),
    state: shipItStateObservation(files.state.text, baseline?.target) };
}

export function replacementObservation(value) {
  const count = (name) => Number.isInteger(value[name]) && value[name] >= 0 ? Math.min(16, value[name]) : 0;
  return { install: installPromiseObservation(value.install), oldPidChecked: value.oldPidChecked === true, oldPidAlive: value.oldPidAlive === true,
    processCountsChecked: value.processCountsChecked === true, baseProcessCount: count("baseProcessCount"),
    candidateProcessCount: count("candidateProcessCount"), newProcessCount: count("newProcessCount"),
    installedVersion: typeof value.installedVersion === "string" && /^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(value.installedVersion) ? value.installedVersion : null,
    installedCdhashChecked: value.installedCdhashChecked === true, installedAsarChecked: value.installedAsarChecked === true,
    installedCandidateCdhashMatches: value.installedCandidateCdhashMatches === true, installedCandidateAsarMatches: value.installedCandidateAsarMatches === true,
    installedBaseCdhashMatches: value.installedBaseCdhashMatches === true, installedBaseAsarMatches: value.installedBaseAsarMatches === true,
    ...(value.shipIt ? { shipIt: shipItDiagnosticObservation(value.shipIt) } : {}),
    ...(value.childExit ? { childExit: childExitObservation(value.childExit) } : {}),
    ...(value.nativeStage ? { nativeStage: { armed: value.nativeStage.armed === true,
      frames: Number.isInteger(value.nativeStage.frames) && value.nativeStage.frames >= 0 ? Math.min(128, value.nativeStage.frames) : 0,
      ...nativeStageObservation(value.nativeStage) } } : {}) };
}

async function readInstallObserver(observer) {
  if (!observer.renderer) return;
  try { observer.last = installPromiseObservation(await observer.renderer.evaluate(replacementProbeExpression("read"), 1000)); }
  catch { observer.renderer.close(); observer.renderer = undefined; }
}

async function reportReplacement(base, candidate, oldPid, observer) {
  await readInstallObserver(observer);
  const shipIt = await readShipItDiagnostics(observer.shipIt).catch(() => shipItDiagnosticObservation());
  const basePids = await findOwnedPids(base.executable).catch(() => undefined);
  const candidatePids = await findOwnedPids(candidate.executable).catch(() => undefined);
  const alive = await run("/bin/ps", ["-p", String(oldPid), "-o", "pid="], { allowFailure: true, timeoutMs: 5000, maxBytes: 4096 });
  const app = path.resolve(base.executable, "../../..");
  const info = await run("/usr/bin/plutil", ["-convert", "json", "-o", "-", path.join(app, "Contents/Info.plist")], { allowFailure: true, timeoutMs: 5000, maxBytes: 65536 });
  let installedVersion;
  try { if (info.exitCode === 0) installedVersion = JSON.parse(info.stdout).CFBundleShortVersionString; } catch {}
  const signature = await run("/usr/bin/codesign", ["-dvvv", app], { allowFailure: true, timeoutMs: 5000, maxBytes: 65536 });
  const cdhash = signature.exitCode === 0 ? /^CDHash=([a-f0-9]{40,64})$/m.exec(signature.stdout + signature.stderr)?.[1] : undefined;
  const asar = await sha256File(path.join(app, "Contents/Resources/app.asar")).catch(() => undefined);
  console.log(JSON.stringify({ schemaVersion: 1, check: "replacement_diagnostics", ...replacementObservation({ install: observer.last,
    oldPidChecked: [0, 1].includes(alive.exitCode), oldPidAlive: alive.exitCode === 0 && alive.stdout.trim() === String(oldPid),
    processCountsChecked: !!basePids && !!candidatePids, baseProcessCount: basePids?.length, candidateProcessCount: candidatePids?.length,
    newProcessCount: basePids && candidatePids ? new Set([...basePids, ...candidatePids].filter((pid) => pid !== oldPid)).size : undefined,
    installedVersion, installedCdhashChecked: !!cdhash, installedAsarChecked: !!asar,
    installedCandidateCdhashMatches: !!cdhash && cdhash === candidate.cdhash, installedCandidateAsarMatches: !!asar && asar === candidate.asarSha256,
    installedBaseCdhashMatches: !!cdhash && cdhash === base.cdhash, installedBaseAsarMatches: !!asar && asar === base.asarSha256, shipIt,
    childExit: observer.handoff?.childExit.read(), nativeStage: observer.handoff?.nativeStage.read(),
  }) }));
}

async function replacement(base, candidate, oldPid, arch, pins, observer) {
  try {
    let lastObservation = 0;
    const pid = await waitFor(async () => {
      if (Date.now() - lastObservation >= 1000) { await readInstallObserver(observer); lastObservation = Date.now(); }
      const pids = await findOwnedPids(base.executable);
      return pids.length === 1 && pids[0] !== oldPid ? pids[0] : false;
    }, { timeoutMs: 180000, code: "native_relaunch_unverified" });
    const installed = await verifyApp(path.resolve(base.executable, "../../.."), { pins, arch });
    check(installed.version === pins.version, "installed_version_mismatch", "failed");
    const occupied = await run("/usr/sbin/lsof", ["-nP", "-iTCP:9229", "-sTCP:LISTEN", "-F", "p"], { allowFailure: true });
    check(!occupied.stdout.trim(), "replacement_diagnostic_port_occupied");
    check((await findOwnedPids(base.executable)).includes(pid), "replacement_owner_unverified");
    process.kill(pid, "SIGUSR1"); // Exact new signed-process diagnostic capability, never a fuse change.
    const main = await connectCdp(9229, pid, { targetType: "node", executable: base.executable, timeoutMs: 30000 });
    const expected = { pid, executable: base.executable, resources: path.resolve(base.executable, "../../Resources"), arch, version: pins.version };
    check(await evaluate(main, mainExpression(attestMain, expected)), "replacement_attestation_unverified");
    return { main, expected, installed };
  } finally {
    // Diagnostic observations never replace any native PID/trust/pass gate.
    await reportReplacement(base, candidate, oldPid, observer).catch(() => {
      console.log(JSON.stringify({ schemaVersion: 1, check: "replacement_diagnostics", diagnosticStatus: "unavailable", install: observer.last }));
    });
    observer.renderer?.close();
  }
}

export async function runUpdateVerification(scenario) {
  const pins = await loadPins();
  const context = await requireCiContext(pins); // No override or injected facts in this live path.
  const checks = ["native_host"];
  let control;
  let feed;
  let executable;
  let installObserver;
  let status = "unverified";
  let code;
  let phase = "fresh_host";
  try {
    check(SCENARIOS.includes(scenario), "scenario_required");
    await ensureFreshHost(pins);
    const temporary = await realpath(process.env.RUNNER_TEMP ?? "");
    check(temporary.startsWith("/Users/runner/") && (await stat(temporary)).isDirectory(), "runner_temporary_unverified");
    const root = await mkdtemp(path.join(temporary, "public-native-update-"));
    const artifacts = pins.artifacts[context.arch];
    if (scenario === "signature") check(artifacts.badSignatureZip, "signature_fixture_unavailable");
    const files = { zip: path.join(root, "candidate.zip"), base: path.join(root, "base.zip"), blockmap: path.join(root, "candidate.blockmap"),
      ...(scenario === "signature" ? { negative: path.join(root, "never-launch-signature-fixture.zip") } : {}) };
    phase = "download";
    await downloadPinned(artifacts.baseZip, files.base);
    await downloadPinned(artifacts.zip, files.zip);
    await downloadPinned(artifacts.zipBlockmap, files.blockmap);
    if (files.negative) {
      const artifact = artifacts.badSignatureZip;
      const url = new URL(artifact.url);
      check(url.origin === "https://github.com" && !url.search && !url.hash && !url.username && !url.password &&
        url.pathname === `/roberttree/Program-ai-desktop-update-tests/releases/download/v${pins.version}/${artifact.name}` &&
        artifact.name.startsWith(`Program-AI-Desktop-mac-${context.arch}.`) &&
        /^Program-AI-Desktop-mac-(arm64|x64)\.[a-z-]+\.zip$/.test(artifact.name) && /^[a-f0-9]{64}$/.test(artifact.sha256) &&
        Number.isSafeInteger(artifact.bytes) && artifact.bytes > 0 && artifact.bytes < 512 * 1024 * 1024, "signature_fixture_pin_invalid");
      await downloadPinned(artifact, files.negative); // Never executed, re-signed, or substituted into the installation.
    }
    checks.push("zip_bytes");
    const baseApp = await extractZip(files.base, path.join(root, "installation"));
    const candidateApp = await extractZip(files.zip, path.join(root, "candidate-verification-only"));
    phase = "base_verify";
    const base = await verifyApp(baseApp, { pins, arch: context.arch, version: pins.baseVersion });
    phase = "candidate_verify";
    const candidate = await verifyApp(candidateApp, { pins, arch: context.arch });
    if (files.negative) {
      phase = "signature_fixture_verify";
      const negative = await extractZip(files.negative, path.join(root, "signature-verification-only-never-launch"));
      await verifyNegativeFixture(negative, candidate, pins, context.arch);
    }
    checks.push("zip_app_signature", "zip_app_ticket");
    executable = base.executable;
    feed = await makeFeed({ pins, arch: context.arch, files });
    const baselineTraffic = feed.select("baseline");
    phase = "base_bootstrap";
    control = await startBase(base, context.arch, pins.baseVersion, feed.url, (next) => { phase = next; });
    checks.push("native_launch");
    phase = "preload_ready";
    await ready(control);
    checks.push("renderer_ready", "signed_out");
    const initial = await checkUpdate(control);
    check(initial.status === "up-to-date" && baselineTraffic.metadata > 0 && baselineTraffic.zip === 0,
      "baseline_feed_not_quiescent");
    phase = "seed";
    const before = await seed(control, root);
    checks.push("sidecar_ready");
    if (scenario !== "positive") {
      phase = "negative_check";
      const traffic = feed.select(scenario);
      await setFeed(control, feed.url);
      const observed = await checkUpdate(control);
      if (scenario === "signature") {
        check(observed.status === "ready" && observed.version === pins.version && traffic.metadata > 0 &&
          traffic.sent >= traffic.expectedBytes, "signature_download_unverified");
        phase = "signature_native_preflight";
        await verifyNativeSignatureRejection(control, base, before, traffic);
      } else {
        const outcome = rejectionOutcome(scenario, observed, traffic);
        check(outcome === "passed", `${scenario}_rejection_${outcome}`, outcome === "failed" ? "failed" : "unverified");
      }
      check(await findOwnedPid(base.executable) === control.expected.pid &&
        await sha256File(path.join(baseApp, "Contents/Resources/app.asar")) === base.asarSha256, "base_changed_after_rejection", "failed");
      await preserved(control, before);
      checks.push("failure_rejected");
      if (scenario === "signature") {
        // The shipping preflight deliberately caches rejection and asks for a
        // restart. Honor that contract; do not reset its promise or SDK state.
        phase = "signature_restart";
        const oldPid = control.expected.pid;
        const quiescent = feed.select("baseline");
        await evaluate(control.main, mainExpression(quitOwnedBase, control.expected));
        control.main.close(); control = undefined;
        await waitFor(async () => (await findOwnedPids(base.executable)).length === 0,
          { timeoutMs: 30000, code: "signature_base_quit_unverified" });
        check(await sha256File(path.join(baseApp, "Contents/Resources/app.asar")) === base.asarSha256,
          "base_changed_after_rejection", "failed");
        control = await startBase(base, context.arch, pins.baseVersion, feed.url, (next) => { phase = next; });
        phase = "signature_restart";
        check(control.expected.pid !== oldPid, "signature_base_restart_unverified");
        await ready(control);
        const restarted = await checkUpdate(control);
        check(restarted.status === "up-to-date" && quiescent.metadata > 0 && quiescent.zip === 0,
          "signature_restart_feed_not_quiescent");
        await preserved(control, before);
      }
    }
    phase = "positive_download";
    const traffic = feed.select("positive");
    await setFeed(control, feed.url);
    const observed = await checkUpdate(control);
    check(observed.status === "ready" && observed.version === pins.version && traffic.zip > 0 && traffic.sent >= artifacts.zip.bytes,
      "valid_update_download_unverified");
    checks.push(scenario === "positive" ? "update_download" : "recovery_download");
    const oldPid = control.expected.pid;
    phase = "native_install";
    // Schedule the real preload request in the existing renderer, then close
    // the owned inspector before that request can trigger native quit/relaunch.
    const renderer = await connectCdp(control.rendererPort, oldPid, { targetType: "page", executable: base.executable, timeoutMs: 5000 }).catch(() => undefined);
    installObserver = { renderer, last: { outcome: "pending", errorClass: "none" }, shipIt: await captureShipItBaseline(base).catch(() => undefined), handoff: control.handoff };
    installObserver.last = installPromiseObservation(await windowValue(control, replacementProbeExpression("schedule")));
    check(await evaluate(control.main, "(()=>{setTimeout(()=>process.getBuiltinModule('inspector').close(),0);return true})()"),
      "install_diagnostic_close_unverified");
    control.main.close();
    control = undefined;
    phase = "replacement";
    const updated = await replacement(base, candidate, oldPid, context.arch, pins, installObserver);
    control = updated;
    check(updated.installed.cdhash === candidate.cdhash && updated.installed.asarSha256 === candidate.asarSha256,
      "installed_candidate_identity_mismatch", "failed");
    checks.push("native_update");
    await ready(control);
    phase = "preservation";
    await preserved(control, before);
    checks.push("state_preserved");
    if (pins.version === "1.0.10") await nativeShellCommandRegression(control, before);
    check(await sha256File(files.zip) === artifacts.zip.sha256 && await sha256File(files.base) === artifacts.baseZip.sha256,
      "pinned_archive_changed", "failed");
    status = "passed";
    phase = "completed";
  } catch (error) {
    status = error instanceof VerificationFailure ? error.kind : "unverified";
    code = error instanceof VerificationFailure ? error.code : "unexpected_harness_error";
  } finally {
    if (status !== "passed" && code === "signed_out_preload_unavailable" && control) await reportReadyFailure(control);
    // Capture the actual pre-cleanup child exit, never a SIGTERM sent by this
    // harness's later owned-process cleanup. No raw stderr is published.
    const handoff = installObserver?.handoff ?? control?.handoff;
    if (status !== "passed" && handoff) console.log(JSON.stringify({ schemaVersion: 1, check: "native_handoff_diagnostics",
      childExit: childExitObservation(handoff.childExit.read()), nativeStage: { armed: handoff.nativeStage.read().armed,
        frames: handoff.nativeStage.read().frames, ...nativeStageObservation(handoff.nativeStage.read()) } }));
    installObserver?.renderer?.close();
    control?.main.close();
    if (executable) {
      const pids = await findOwnedPids(executable).catch(() => undefined);
      if (!pids || pids.length > 1) {
        status = "unverified"; code = "cleanup_ownership_unverified"; phase = "cleanup";
      }
      if (pids?.length === 1) {
        try { await terminateOwned(executable, pids[0]); checks.push("cleanup"); }
        catch { status = "unverified"; code = "cleanup_ownership_unverified"; phase = "cleanup"; }
      }
    }
    await feed?.close();
  }
  console.log(JSON.stringify(caseReceipt({ scenario, arch: context.arch, version: pins.version, status, code, phase,
    sourceCommit: pins.source.commit, candidateZipSha256: pins.artifacts[context.arch].zip.sha256,
    baseZipSha256: pins.artifacts[context.arch].baseZip.sha256 })));
  await emitReceipt({ flow: "update", arch: context.arch, version: pins.version, status, checks, code });
  return status;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  Promise.resolve().then(() => runUpdateVerification(parseScenario(process.argv.slice(2))))
    .then((status) => { if (status !== "passed") process.exitCode = 1; })
    .catch((error) => {
      console.log(JSON.stringify({ schemaVersion: 1, flow: "update", status: "unverified",
        code: error instanceof VerificationFailure ? error.code : "entrypoint_unverified" }));
      process.exitCode = 1;
    });
}
