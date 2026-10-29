import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath, stat } from "node:fs/promises";
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
  "base_attest", "base_feed", "base_debugger_resume", "base_debugger_disable", "preload_ready", "seed", "negative_check", "positive_download", "native_install",
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
  return traffic.sent >= traffic.expectedBytes && observed.errorClass === "signature" ? "passed" : "unverified";
}

export function validatePreservation(before, after) {
  return before.marker === after.marker && before.store === after.store && before.session === after.session &&
    before.title === after.title && before.messages.length > 0 && before.messages.every((id) => after.messages.includes(id)) &&
    after.signedOut === true;
}

export function syntheticShellCommand(marker) {
  check(/^Public native update canary [a-f0-9-]{36}\n$/.test(marker), "synthetic_marker_invalid");
  return `printf '%s' '${marker}' > update-canary.txt`;
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

async function startBase(base, arch, version, feedUrl, observePhase) {
  const port = await unusedPort();
  observePhase("base_spawn");
  const child = spawn(base.executable, [`--inspect-brk=127.0.0.1:${port}`], {
    env: applicationEnvironment(), stdio: ["ignore", "ignore", "pipe"],
  });
  child.stderr.on("data", () => {}); // Consume but never retain app diagnostics.
  child.on("error", () => {});
  check(Number.isSafeInteger(child.pid) && child.pid > 1, "owned_spawn_unverified");
  observePhase("base_diagnostic_connect");
  const main = await connectCdp(port, child.pid, { targetType: "node", executable: base.executable, timeoutMs: 30000 });
  const expected = { pid: child.pid, executable: base.executable, resources: path.resolve(base.executable, "../../Resources"), arch, version };
  try { await bootstrapMain(main, expected, feedUrl, observePhase); }
  catch (error) { main.close(); throw error; }
  return { main, expected, child };
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
  await localRequest(connection, `/session/${session.id}/shell`, project,
    { agent: "build", command: syntheticShellCommand(marker) });
  const messages = messageIds(await localRequest(connection, `/session/${session.id}/message`, project));
  check(await readFile(path.join(project, "update-canary.txt"), "utf8") === marker, "shell_marker_unverified");
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

async function replacement(base, oldPid, arch, pins) {
  const pid = await waitFor(async () => {
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
}

export async function runUpdateVerification(scenario) {
  const pins = await loadPins();
  const context = await requireCiContext(pins); // No override or injected facts in this live path.
  const checks = ["native_host"];
  let control;
  let feed;
  let executable;
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
      const outcome = rejectionOutcome(scenario, observed, traffic);
      check(outcome === "passed", `${scenario}_rejection_${outcome}`, outcome === "failed" ? "failed" : "unverified");
      check(await findOwnedPid(base.executable) === control.expected.pid &&
        await sha256File(path.join(baseApp, "Contents/Resources/app.asar")) === base.asarSha256, "base_changed_after_rejection", "failed");
      await preserved(control, before);
      checks.push("failure_rejected");
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
    await windowValue(control, "(()=>{setTimeout(()=>void window.api.updater.install().catch(()=>{}),1500);return true})()");
    check(await evaluate(control.main, "(()=>{setTimeout(()=>process.getBuiltinModule('inspector').close(),0);return true})()"),
      "install_diagnostic_close_unverified");
    control.main.close();
    control = undefined;
    phase = "replacement";
    const updated = await replacement(base, oldPid, context.arch, pins);
    control = updated;
    check(updated.installed.cdhash === candidate.cdhash && updated.installed.asarSha256 === candidate.asarSha256,
      "installed_candidate_identity_mismatch", "failed");
    checks.push("native_update");
    await ready(control);
    phase = "preservation";
    await preserved(control, before);
    checks.push("state_preserved");
    check(await sha256File(files.zip) === artifacts.zip.sha256 && await sha256File(files.base) === artifacts.baseZip.sha256,
      "pinned_archive_changed", "failed");
    status = "passed";
    phase = "completed";
  } catch (error) {
    status = error instanceof VerificationFailure ? error.kind : "unverified";
    code = error instanceof VerificationFailure ? error.code : "unexpected_harness_error";
  } finally {
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
