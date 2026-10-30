import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  SCENARIOS, bootstrapMain, byteRange, caseReceipt, evaluatePaused, loopbackUrl, metadata, parseScenario, pausedCallFrame,
  createInstallPromiseObserver, createNativeSignatureObserver, installPromiseObservation, nativeShellCommandFixture, payloadChunk,
  rejectionOutcome, replacementObservation, shellSeedObservation, shipItDiagnosticObservation, shipItLogObservation, shipItReadPlan,
  shipItStateObservation, signatureInstallOutcome, syntheticShellCommand, updaterObservation, validatePreservation,
} from "./verify-update.mjs";

const traffic = () => ({ metadata: 1, zip: 1, sent: 100, expectedBytes: 100, corrupted: 1, interrupted: 1 });
const state = () => ({ marker: "synthetic\n", store: "unsent canary", session: "session_synthetic_1",
  title: "Synthetic shell chat", messages: ["message_1", "message_2"], signedOut: true });

test("ShipIt log read policy admits only new appended bytes and refuses replaced/truncated/unsafe prior files", () => {
  const before = { status: "owned", dev: 1, ino: 2, size: 100, mtimeMs: 1, ctimeMs: 1 };
  const after = { ...before, size: 70000 };
  assert.deepEqual(shipItReadPlan(before, after), { status: "observed", start: 4464, length: 65536, tailTruncated: true });
  assert.equal(shipItReadPlan(before, before).status, "unchanged");
  assert.equal(shipItReadPlan(before, { ...after, ino: 3 }).status, "replaced");
  assert.equal(shipItReadPlan(before, { ...before, size: 99 }).status, "truncated");
  assert.equal(shipItReadPlan({ status: "unsafe" }, after).status, "baseline_unavailable");
  assert.equal(shipItReadPlan(before, { status: "unsafe" }).status, "unsafe");
  assert.equal(shipItReadPlan({ status: "absent" }, { ...after, size: 9 * 1024 * 1024 }).status, "size_limit");
  assert.equal(shipItReadPlan(before, before, true).status, "unchanged");
  assert.equal(shipItReadPlan(before, { ...before, ino: 3, size: 500 }, true).status, "observed");
  assert.equal(shipItReadPlan(before, after, true).status, "size_limit");
});

test("ShipIt tail classifier emits only known marker booleans and bounded installer enums, never free text", () => {
  const text = 'privateURL?token=secret Error Domain=SQRLInstallerErrorDomain Code=-3 private/path\nSQRLInstallerErrorDomain error -9\nSQRLInstallerErrorDomain Code=-10\nMoving bundle from private/path to other\n';
  const result = shipItLogObservation([text, "Could not read update request private secret"]);
  assert.deepEqual(result.installerCodes, [-9, -3]);
  assert.equal(result.bundleMoveStarted, true);
  assert.equal(result.requestReadError, true);
  assert.doesNotMatch(JSON.stringify(result), /private|URL|token|secret|path/);
  assert.equal(shipItLogObservation(["unknown private failure"]).unknownTextSeen, true);
  assert.equal(shipItLogObservation(["SQRLInstallerErrorDomain Code=-1" + "x".repeat(70000)]).installerCodes.length, 0);
  const phases = shipItLogObservation(["Detected this as an install request\nBeginning installation\nInstallation error: private/path\nShipIt quitting",
    "Detected this as a launch request\nCould not launch application at secretURL"]);
  assert.equal(phases.installRequestMarker, true);
  assert.equal(phases.installationBeginMarker, true);
  assert.equal(phases.installationErrorMarker, true);
  assert.equal(phases.launchFailureMarker, true);
  assert.equal(phases.launchSuccessMarker, false);
  assert.equal(phases.installationCompletedMarker, false);
  assert.equal(phases.unknownTextSeen, false);
  assert.doesNotMatch(JSON.stringify(phases), /private|path|secretURL/);
});

test("ShipIt JSON projection binds target to the owned base and emits no URL or extra state keys", () => {
  const target = "/Users/runner/work/_temp/public-native-update-a1B2c3/installation/Program AI Desktop.app";
  const result = shipItStateObservation(JSON.stringify({ targetBundleURL: "file://" + target.replaceAll(" ", "%20"),
    updateBundleURL: "file:///private/staged.app", bundleIdentifier: "com.programai.desktop", launchAfterInstallation: true,
    useUpdateBundleName: false, secret: "never emitted" }), target);
  assert.deepEqual(result, { jsonValid: true, targetMatches: true, bundleMatches: true, localUpdate: true, launchAfterInstallation: true, useUpdateBundleName: false });
  assert.doesNotMatch(JSON.stringify(result), /Users|private|file:|secret|emitted/);
  assert.equal(shipItStateObservation('{"targetBundleURL":"https://private.invalid"}', target).targetMatches, false);
  assert.equal(shipItStateObservation("x".repeat(65537), target).jsonValid, false);
  const scrubbed = shipItDiagnosticObservation({ ...result, files: { stderr: { status: "raw private error", tailTruncated: true } }, logs: { installerCodes: [-1, -99, "secret", -1], raw: "private" }, state: result });
  assert.deepEqual(scrubbed.logs.installerCodes, [-1]);
  assert.equal(scrubbed.files.stderr.status, "unavailable");
  assert.doesNotMatch(JSON.stringify(scrubbed), /raw|private|secret|99/);
});

test("actual install promise observer captures resolution/rejection without raw errors or mutable snapshot inference", async () => {
  const resolved = createInstallPromiseObserver(() => Promise.resolve());
  const snapshot = resolved.read(); snapshot.outcome = "resolved";
  assert.equal(resolved.read().outcome, "pending");
  resolved.start(); await Promise.resolve();
  assert.deepEqual(resolved.read(), { outcome: "resolved", errorClass: "none" });
  for (const [message, errorClass] of [["code signature invalid private-token", "signature"], ["Update is not ready private-token", "not_ready"],
    ["EACCES private path", "permission"], ["network timeout secretURL", "network"], ["private other failure", "other"]]) {
    const rejected = createInstallPromiseObserver(() => Promise.reject(new Error(message)));
    rejected.start(); await Promise.resolve();
    assert.deepEqual(rejected.read(), { outcome: "rejected", errorClass });
    assert.doesNotMatch(JSON.stringify(rejected.read()), /private|secretURL/);
  }
  const synchronous = createInstallPromiseObserver(() => { throw new Error("private failure"); });
  synchronous.start(); assert.equal(synchronous.read().outcome, "rejected");
  assert.throws(() => installPromiseObservation({ outcome: "rejected", errorClass: "raw private error" }), { code: "install_observation_invalid" });
});

test("replacement diagnostics bound counts and expose only version/comparison facts, never PIDs, paths or hashes", () => {
  const result = replacementObservation({ install: { outcome: "pending", errorClass: "none" }, oldPidChecked: true, oldPidAlive: false,
    processCountsChecked: true, baseProcessCount: 0, candidateProcessCount: 0, newProcessCount: 99, installedVersion: "1.0.10",
    installedCdhashChecked: true, installedAsarChecked: true, installedCandidateCdhashMatches: true, installedCandidateAsarMatches: true,
    pid: 123456, path: "/Users/private", stderr: "secret", cdhash: "a".repeat(40), asarSha256: "b".repeat(64) });
  assert.equal(result.newProcessCount, 16);
  assert.equal(result.installedVersion, "1.0.10");
  assert.equal(result.installedCandidateCdhashMatches, true);
  assert.doesNotMatch(JSON.stringify(result), /123456|Users|secret|aaaa|bbbb/);
  assert.equal(replacementObservation({ ...result, installedVersion: "private value" }).installedVersion, null);
});

test("native1.0.10 shell regression uses real LF and keeps quoted substitution literal through a profile-free parser", () => {
  const fixture = nativeShellCommandFixture("/Users/runner/work/_temp/public-native-update-a1B2c3/synthetic-project");
  assert.equal(fixture.command.split("\n").length, 2);
  assert.match(fixture.command, /'literal \$\(\/usr\/bin\/printf MUST_STAY_LITERAL\)'/);
  assert.equal(new Set([...fixture.command.matchAll(/(?:>|>>) '([^']+)'/g)].map((match) => match[1])).size, 1);
  const stdoutOnly = fixture.command.replace(/ > '[^']+'/g, "").replace(/ >> '[^']+'/g, "");
  const actual = execFileSync("/bin/bash", ["--noprofile", "--norc", "-c", stdoutOnly], {
    env: { PATH: "/usr/bin:/bin" }, encoding: "utf8", timeout: 5000, maxBuffer: 4096,
  });
  assert.equal(actual, fixture.expected);
  assert.throws(() => nativeShellCommandFixture("/private/tmp/project"), { code: "synthetic_project_invalid" });
});

test("paused evaluation uses only the observed call frame and rejects asynchronous or exceptional results", async () => {
  assert.equal(pausedCallFrame({ callFrames: [{ callFrameId: "owned-frame" }] }), "owned-frame");
  for (const event of [{}, { callFrames: [] }, { callFrames: [{ callFrameId: "" }] }, { callFrames: [{ callFrameId: "x".repeat(1025) }] }])
    assert.equal(pausedCallFrame(event), undefined);
  const calls = [];
  const main = { send: async (...args) => { calls.push(args); return { result: { type: "boolean", value: true } }; } };
  assert.equal(await evaluatePaused(main, "owned-frame", "true"), true);
  assert.equal(calls[0][0], "Debugger.evaluateOnCallFrame");
  assert.deepEqual(calls[0][1], { callFrameId: "owned-frame", expression: "true", returnByValue: true, silent: true });
  assert.equal(calls[0][2], 20000);
  assert.equal(Object.hasOwn(calls[0][1], "awaitPromise"), false);
  for (const result of [{ exceptionDetails: {} }, { result: { type: "object", subtype: "promise" } }, { result: { type: "boolean", value: false } }])
    await assert.rejects(evaluatePaused({ send: async () => result }, "owned-frame", "true"), { code: "paused_evaluation_unverified" });
});

function bootstrapFixture(failMethod) {
  let paused;
  const calls = [], phases = [];
  return { calls, phases, client: {
    onEvent(method, callback) { assert.equal(method, "Debugger.paused"); paused = callback; return () => { paused = undefined; }; },
    async send(method, params) {
      calls.push({ method, params });
      if (method === failMethod) throw Object.assign(new Error("fixture only"), { code: "diagnostic_command_timeout" });
      if (method === "Runtime.runIfWaitingForDebugger") paused({ callFrames: [{ callFrameId: "owned-frame" }] });
      return { result: { type: "boolean", value: true } };
    },
  }, observe: (phase) => phases.push(phase) };
}

test("actual bootstrap attests and sets loopback synchronously before resume, with fixed command subphases", async () => {
  const fixture = bootstrapFixture();
  await bootstrapMain(fixture.client, {}, "http://127.0.0.1:1234/", fixture.observe);
  assert.deepEqual(fixture.calls.map((call) => call.method), ["Debugger.enable", "Runtime.runIfWaitingForDebugger",
    "Debugger.evaluateOnCallFrame", "Debugger.evaluateOnCallFrame", "Debugger.resume", "Debugger.disable"]);
  assert.deepEqual(fixture.phases, ["base_debugger_enable", "base_waiting_release", "base_pause_wait", "base_attest",
    "base_feed", "base_debugger_resume", "base_debugger_disable"]);
  assert.match(fixture.calls[3].params.expression, /setFeedURL/);
  assert.equal(fixture.calls[2].params.callFrameId, fixture.calls[3].params.callFrameId);
  for (const phase of fixture.phases) assert.equal(caseReceipt({ scenario: "positive", arch: "x64", version: "1.0.9", status: "unverified", phase }).phase, phase);
});

test("bootstrap failures retain the exact fixed failing command phase instead of claiming a debugger cause", async () => {
  for (const [method, phase] of [["Debugger.enable", "base_debugger_enable"], ["Runtime.runIfWaitingForDebugger", "base_waiting_release"],
    ["Debugger.evaluateOnCallFrame", "base_attest"], ["Debugger.resume", "base_debugger_resume"], ["Debugger.disable", "base_debugger_disable"]]) {
    const fixture = bootstrapFixture(method);
    await assert.rejects(bootstrapMain(fixture.client, {}, "http://127.0.0.1:1234/", fixture.observe), { code: "diagnostic_command_timeout" });
    assert.equal(fixture.phases.at(-1), phase);
  }
});

test("live scenario is explicit and restricted to approved cases", () => {
  for (const scenario of SCENARIOS) assert.equal(parseScenario(["--scenario", scenario]), scenario);
  for (const args of [[], ["positive"], ["--scenario", "all"], ["--scenario", "positive", "--spoof-ci"], ["--scenario", "../../"]]) {
    assert.throws(() => parseScenario(args), { code: "scenario_required" });
  }
});

test("feed override accepts only exact IPv4 loopback HTTP endpoints", () => {
  assert.equal(loopbackUrl("http://127.0.0.1:43123/").origin, "http://127.0.0.1:43123");
  for (const value of ["https://127.0.0.1:43123/", "http://localhost:43123/", "http://127.0.0.2:43123/", "http://example.com:43123/",
    "http://a:b@127.0.0.1:43123/", "http://127.0.0.1/", "http://127.0.0.1:43123/#private"]) {
    assert.throws(() => loopbackUrl(value), { code: "loopback_url_invalid" });
  }
});

test("single byte ranges support ordinary updater requests and reject ambiguous ranges", () => {
  assert.deepEqual(byteRange(undefined, 100), { start: 0, end: 99, length: 100, partial: false });
  assert.deepEqual(byteRange("bytes=2-4", 100), { start: 2, end: 4, length: 3, partial: true });
  assert.deepEqual(byteRange("bytes=90-", 100), { start: 90, end: 99, length: 10, partial: true });
  assert.deepEqual(byteRange("bytes=90-200", 100), { start: 90, end: 99, length: 10, partial: true });
  for (const value of ["bytes=100-", "bytes=8-2", "bytes=-10", "bytes=0-1,3-4", "items=0-10", "bytes=9007199254740992-"]) {
    assert.equal(byteRange(value, 100), undefined);
  }
});

test("feed YAML is generated only from bounded exact identity and digest fields", () => {
  const sha512 = "A".repeat(86) + "==";
  const yaml = metadata({ version: "1.0.9", name: "Program-AI-Desktop-mac-arm64.zip", bytes: 100, sha512 });
  assert.match(yaml, /^version: 1\.0\.9\nfiles:/);
  assert.match(yaml, /url: Program-AI-Desktop-mac-arm64\.zip/);
  assert.doesNotMatch(yaml, /github|token|password|\.dmg|blockMapSize/);
  assert.match(metadata({ version: "1.0.9", name: "Program-AI-Desktop-mac-x64.bad-signature.zip", bytes: 100, sha512 }), /bad-signature\.zip/);
  for (const values of [{ version: "9\nforged: true" }, { name: "../../other.zip" }, { bytes: 0 }, { sha512: "wrong" }]) {
    assert.throws(() => metadata({ version: "1.0.9", name: "Program-AI-Desktop-mac-arm64.zip", bytes: 100, sha512, ...values }), { code: "feed_metadata_invalid" });
  }
});

test("updater observations cannot expose free-form errors or credentials", () => {
  const result = updaterObservation({ status: "error", message: "sha512 checksum mismatch at https://private.invalid/?token=secret", password: "secret" });
  assert.deepEqual(result, { status: "error", errorClass: "checksum" });
  assert.deepEqual(updaterObservation({ status: "error", message: "Code signature invalid: private path" }), { status: "error", errorClass: "signature" });
  assert.deepEqual(updaterObservation({ status: "ready", version: "1.0.9", message: "secret" }), { status: "ready", version: "1.0.9", errorClass: "none" });
  assert.deepEqual(updaterObservation({ status: "ready", version: "private-version" }), { status: "ready", errorClass: "none" });
  assert.deepEqual(updaterObservation({ status: "invented", message: "secret" }), { status: "unknown", errorClass: "none" });
});

test("network rejection requires actual feed contact and an observed controller error", () => {
  for (const scenario of ["offline", "unavailable"]) {
    assert.equal(rejectionOutcome(scenario, { status: "error" }, traffic()), "passed");
    assert.equal(rejectionOutcome(scenario, { status: "idle" }, traffic()), "unverified");
    assert.equal(rejectionOutcome(scenario, { status: "error" }, { ...traffic(), metadata: 0 }), "unverified");
    assert.equal(rejectionOutcome(scenario, { status: "ready" }, traffic()), "failed");
  }
});

test("interrupted rejection needs transmitted data and deliberate socket interruption", () => {
  assert.equal(rejectionOutcome("interrupted", { status: "error" }, traffic()), "passed");
  assert.equal(rejectionOutcome("interrupted", { status: "error" }, { ...traffic(), interrupted: 0 }), "unverified");
  assert.equal(rejectionOutcome("interrupted", { status: "error" }, { ...traffic(), sent: 0 }), "unverified");
});

test("checksum rejection is never inferred from an unrelated error or incomplete transfer", () => {
  assert.equal(rejectionOutcome("checksum", { status: "error", errorClass: "checksum" }, traffic()), "passed");
  for (const partial of [{ sent: 99 }, { corrupted: 0 }]) {
    assert.equal(rejectionOutcome("checksum", { status: "error", errorClass: "checksum" }, { ...traffic(), ...partial }), "unverified");
  }
  assert.equal(rejectionOutcome("checksum", { status: "error", errorClass: "network" }, traffic()), "unverified");
});

test("download-ready and controller error text alone never claim native signature acceptance or rejection", () => {
  for (const observed of [{ status: "error", errorClass: "signature" }, { status: "ready" }, { status: "installing" }, { status: "error", errorClass: "checksum" }])
    assert.equal(rejectionOutcome("signature", observed, traffic()), "unverified");
});

test("read-only native observer keeps product listeners and scrubs errors to actual Squirrel enums", () => {
  const native = new EventEmitter(), app = new EventEmitter();
  let sdkErrors = 0, nativeChecks = 0;
  const sdk = () => { sdkErrors++; };
  native.on("error", sdk);
  native.checkForUpdates = () => { nativeChecks++; };
  const originalCheck = native.checkForUpdates;
  const observer = createNativeSignatureObserver(native, app);
  const secret = "private path/token never emitted";
  native.emit("error", Object.assign(new Error(secret), { domain: "SQRLCodeSignatureErrorDomain", code: -1 }));
  assert.deepEqual(observer.read(), { errors: 1, signatureErrors: 1, signatureCode: -1, downloaded: false, beforeQuit: false });
  assert.doesNotMatch(JSON.stringify(observer.read()), /private|token|path/);
  // Mere words in a generic error do not count as a signature-domain error.
  native.emit("error", new Error("Code signature failed " + secret));
  assert.equal(observer.read().errors, 2);
  assert.equal(observer.read().signatureErrors, 1);
  native.emit("update-downloaded"); app.emit("before-quit");
  assert.equal(observer.read().downloaded, true);
  assert.equal(observer.read().beforeQuit, true);
  observer.close();
  assert.deepEqual(native.listeners("error"), [sdk]);
  assert.equal(native.listenerCount("update-downloaded"), 0);
  assert.equal(app.listenerCount("before-quit"), 0);
  assert.equal(native.checkForUpdates, originalCheck);
  assert.equal(nativeChecks, 0);
  assert.equal(sdkErrors, 2);
});

test("signature acceptance needs real preload rejection, native signature enum and unchanged process/code/sidecar", () => {
  const valid = { native: { errors: 1, signatureErrors: 1, signatureCode: -1, downloaded: false, beforeQuit: false },
    attempt: { rejected: true, resolved: false }, originalPid: true, baseAsar: true, sidecarUnchanged: true, completePayload: true };
  assert.equal(signatureInstallOutcome(valid), "passed");
  for (const changed of [{ originalPid: false }, { baseAsar: false }, { sidecarUnchanged: false },
    { native: { ...valid.native, downloaded: true } }, { native: { ...valid.native, beforeQuit: true } },
    { attempt: { rejected: false, resolved: true } }]) assert.equal(signatureInstallOutcome({ ...valid, ...changed }), "failed");
  for (const changed of [{ completePayload: false }, { attempt: { rejected: false, resolved: false } },
    { native: { ...valid.native, errors: 0 } }, { native: { ...valid.native, signatureCode: null } },
    { native: { ...valid.native, signatureErrors: 0 } }, { native: { ...valid.native, errors: 2 } }])
    assert.equal(signatureInstallOutcome({ ...valid, ...changed }), "unverified");
});

test("downgrade requires metadata observation but no payload download", () => {
  assert.equal(rejectionOutcome("downgrade", { status: "up-to-date" }, { ...traffic(), zip: 0 }), "passed");
  assert.equal(rejectionOutcome("downgrade", { status: "up-to-date" }, traffic()), "failed");
  assert.equal(rejectionOutcome("downgrade", { status: "ready" }, { ...traffic(), zip: 0 }), "failed");
  assert.equal(rejectionOutcome("downgrade", { status: "error" }, { ...traffic(), zip: 0 }), "unverified");
  assert.equal(rejectionOutcome("downgrade", { status: "up-to-date" }, { ...traffic(), metadata: 0, zip: 0 }), "unverified");
});

test("checksum fault injection changes only a copy of the transmitted first chunk", () => {
  const original = Buffer.from("authenticated zip bytes");
  const changed = payloadChunk(original, "checksum", false);
  assert.equal(original.toString(), "authenticated zip bytes");
  assert.equal(changed.corrupted, true);
  assert.notDeepEqual(changed.bytes, original);
  assert.deepEqual(changed.bytes.subarray(1), original.subarray(1));
  assert.equal(payloadChunk(original, "checksum", true).bytes, original);
  assert.equal(payloadChunk(original, "positive", false).bytes, original);
  assert.equal(payloadChunk(original, "signature", false).corrupted, false);
});

test("synthetic shell marker is bounded, quoted and uses no inference endpoint", () => {
  const marker = "Public native update canary 11111111-2222-3333-4444-555555555555\n";
  const project = "/Users/runner/work/_temp/public-native-update-a1B2c3/synthetic-project";
  const command = syntheticShellCommand(marker, project);
  assert.equal(command, `/usr/bin/printf '%s\\n' '${marker.slice(0, -1)}' > '${project}/update-canary.txt'`);
  assert.doesNotMatch(command, /[\r\n]/);
  assert.match(command, /%s\\n/);
  for (const value of ["secret", marker + "x", "Public native update canary ';rm -rf /\n"]) {
    assert.throws(() => syntheticShellCommand(value, project), { code: "synthetic_marker_invalid" });
  }
  for (const target of ["/tmp/project", project + "/..", project.replace("runner", "owner"), project + "'", "relative"])
    assert.throws(() => syntheticShellCommand(marker, target), { code: "synthetic_project_invalid" });
});

test("canary printf format has one actual backslash and produces exact LF bytes through a real profile-free shell", () => {
  const expected = "Public native update canary 11111111-2222-3333-4444-555555555555\n";
  const generated = syntheticShellCommand(expected, "/Users/runner/work/_temp/public-native-update-a1B2c3/synthetic-project");
  const separator = generated.indexOf(" > '");
  assert.ok(separator > 0);
  const command = generated.slice(0, separator); // stdout-only; no file is created.
  const format = /\/usr\/bin\/printf '([^']+)'/.exec(command)?.[1];
  assert.deepEqual([...Buffer.from(format)], [37, 115, 92, 110]);
  const parse = (value) => execFileSync("/bin/bash", ["--noprofile", "--norc", "-c", value], {
    env: { PATH: "/usr/bin:/bin" }, encoding: "utf8", timeout: 5000, maxBuffer: 4096,
  });
  const actual = parse(command);
  assert.equal(actual, expected);
  assert.equal(Buffer.byteLength(actual), 65);
  assert.equal(Buffer.from(actual).at(-1), 10);
  assert.equal(createHash("sha256").update(actual).digest("hex"), createHash("sha256").update(expected).digest("hex"));
  const overescaped = parse(command.replace("%s\\n", "%s\\\\n"));
  assert.notEqual(overescaped, expected);
  assert.equal(overescaped.endsWith("\\n"), true);
});

test("shell canary diagnostics expose fixed state, optional actual exit and byte/digest facts without tool output", () => {
  const expected = "Public native update canary 11111111-2222-3333-4444-555555555555\n";
  const response = { info: { private: "never logged" }, parts: [{ type: "tool", state: { status: "completed", metadata: { output: "private tool output" } } }] };
  const good = shellSeedObservation(response, expected, expected);
  assert.equal(good.toolStatus, "completed");
  assert.equal(good.exitCode, null); // Current shell API does not expose an exit code.
  assert.equal(good.digestMatches, true);
  assert.equal(good.actualEndsInLf, true);
  assert.equal(good.literalBackslashNMatches, false);
  const escaped = shellSeedObservation(response, expected, expected.slice(0, -1) + "\\n");
  assert.equal(escaped.digestMatches, false);
  assert.equal(escaped.literalBackslashNMatches, true);
  response.parts[0].state.metadata.exit = 7;
  assert.equal(shellSeedObservation(response, expected, undefined).exitCode, 7);
  assert.equal(shellSeedObservation(response, expected, undefined).fileRead, false);
  assert.doesNotMatch(JSON.stringify(good), /private|never logged|native update canary/);
});

test("preservation requires real saved messages, exact marker/store and signed-out state", () => {
  assert.equal(validatePreservation(state(), { ...state(), messages: [...state().messages, "new_message"] }), true);
  for (const changed of [{ marker: "changed" }, { store: "changed" }, { session: "other_session" }, { title: "other" },
    { messages: ["message_1"] }, { signedOut: false }]) assert.equal(validatePreservation(state(), { ...state(), ...changed }), false);
  assert.equal(validatePreservation({ ...state(), messages: [] }, state()), false);
});

test("public case receipt is deliberately narrower than paid coding or editor restoration", () => {
  const result = caseReceipt({ scenario: "signature", arch: "x64", version: "1.0.9", status: "unverified", code: "signature_fixture_unavailable",
    password: "secret", stdout: "secret", file: "private", session: "private" });
  assert.equal(result.paidCoding, false);
  assert.equal(result.productionAccount, false);
  assert.equal(result.editorDraftRestoration, "not_claimed");
  assert.equal(result.preservationScope, "sidecar_shell_chat_and_preload_store_canary");
  assert.doesNotMatch(JSON.stringify(result), /secret|private|password|stdout/);
  assert.throws(() => caseReceipt({ scenario: "all", arch: "x64", version: "1.0.9", status: "passed" }), { code: "case_receipt_invalid" });
  assert.equal(caseReceipt({ scenario: "positive", arch: "x64", version: "1.0.9", status: "unverified", phase: "base_verify" }).phase, "base_verify");
  assert.throws(() => caseReceipt({ scenario: "positive", arch: "x64", version: "1.0.9", status: "unverified", phase: "private path" }), { code: "case_receipt_invalid" });
  const identity = { sourceCommit: "a".repeat(40), candidateZipSha256: "b".repeat(64), baseZipSha256: "c".repeat(64) };
  assert.equal(caseReceipt({ scenario: "positive", arch: "arm64", version: "1.0.9", status: "passed", ...identity }).sourceCommit, identity.sourceCommit);
  assert.throws(() => caseReceipt({ scenario: "positive", arch: "arm64", version: "1.0.9", status: "passed", ...identity,
    sourceCommit: "secret source URL" }), { code: "case_receipt_identity_invalid" });
});

test("signature restart schedules owned inspector teardown before normal quit and detaches before PID wait", async () => {
  const source = await readFile(new URL("./verify-update.mjs", import.meta.url), "utf8");
  const quit = source.slice(source.indexOf("function quitOwnedBase("), source.indexOf("export function validatePreservation("));
  assert.match(quit, /process\.pid !== expected\.pid/);
  assert.match(quit, /electron\.app\.getVersion\(\) !== expected\.version/);
  assert.ok(quit.indexOf("setTimeout(() => {") < quit.indexOf('process.getBuiltinModule("inspector").close()'));
  assert.ok(quit.indexOf('process.getBuiltinModule("inspector").close()') < quit.indexOf("electron.app.quit()"));
  assert.match(quit, /\}, 150\);\s+return true/);
  const restart = source.slice(source.indexOf('phase = "signature_restart";'), source.indexOf('phase = "positive_download";'));
  assert.ok(restart.indexOf("await evaluate(control.main, mainExpression(quitOwnedBase, control.expected))") < restart.indexOf("control.main.close()"));
  assert.ok(restart.indexOf("control.main.close()") < restart.indexOf("await waitFor("));
  assert.match(restart, /base\.asarSha256/);
  assert.match(restart, /startBase\(base, context\.arch, pins\.baseVersion, feed\.url/);
  assert.match(restart, /await preserved\(control, before\)/);
  assert.doesNotMatch(quit + restart, /quitAndInstall|pending\s*=|squirrelDownloadedUpdate\s*=/);
});

test("live entrypoint remains CI-gated and never uses source imports, global kills or security bypasses", async () => {
  const source = await readFile(new URL("./verify-update.mjs", import.meta.url), "utf8");
  assert.ok(source.indexOf("await requireCiContext(pins)") < source.indexOf("await ensureFreshHost(pins)"));
  assert.ok(source.indexOf("await ensureFreshHost(pins)") < source.indexOf("await downloadPinned(artifacts.baseZip"));
  assert.doesNotMatch(source, /killall|pkill|flipFuses|--no-sandbox|--ignore-certificate-errors|xattr.*-d|tccutil|\.\.\/packages|SessionPrompt|sqlite/);
  assert.match(source, /scenario !== "positive"/);
  assert.match(source, /await preserved\(control, before\)/);
  assert.match(source, /updated\.installed\.cdhash === candidate\.cdhash/);
  assert.match(source, /signature-verification-only-never-launch/);
  const bootstrap = source.slice(source.indexOf("export async function bootstrapMain("), source.indexOf("async function startBase("));
  assert.ok(bootstrap.indexOf("mainExpression(changeFeed, expected, feedUrl)") < bootstrap.indexOf('main.send("Debugger.resume")'));
  assert.doesNotMatch(bootstrap, /await evaluate\(main|awaitPromise/);
  assert.match(source, /feed\.select\("baseline"\)/);
  assert.match(source, /baselineTraffic\.zip === 0/);
  assert.match(source, /await verifyNativeSignatureRejection\(control, base, before, traffic\)/);
  assert.match(source, /window\.api\.updater\.install\(\)\.then/);
  assert.match(source, /app\.quit\(\)/);
  assert.match(source, /signature_restart_feed_not_quiescent/);
  assert.ok(source.indexOf("await verifyNativeSignatureRejection(control, base, before, traffic)") < source.indexOf('phase = "signature_restart"'));
  const nativeObserver = source.slice(source.indexOf("export function createNativeSignatureObserver("), source.indexOf("export function signatureInstallOutcome("));
  assert.doesNotMatch(nativeObserver, /\.emit\(|checkForUpdates|quitAndInstall|setFeedURL|preventDefault|\.message/);
  const shipItReader = source.slice(source.indexOf("async function shipItCacheOwned("), source.indexOf("export function replacementObservation("));
  assert.match(shipItReader, /constants\.O_RDONLY \| constants\.O_NOFOLLOW/);
  assert.doesNotMatch(shipItReader, /writeFile|appendFile|unlink|rm\(|launchctl|\.chmod\(|\.chown\(/);
  assert.ok(source.indexOf("shipIt: await captureShipItBaseline(base)") < source.indexOf('replacementProbeExpression("schedule")'));
  assert.match(source, /logs: shipItLogObservation\(\[files\.stderr\.text \?\? "", files\.stdout\.text \?\? ""\]\)/);
  assert.doesNotMatch(source, /console\.(?:error|log)\(error|JSON\.stringify\(connection|Authorization.*console/);
  assert.match(source, /installObserver\.last = installPromiseObservation/);
  assert.match(source, /targetType: "page", executable: base\.executable/);
  assert.match(source, /check: "replacement_diagnostics"/);
  assert.match(source, /if \(pins\.version === "1\.0\.10"\) await nativeShellCommandRegression/);
  assert.doesNotMatch(source, /window\.api\.updater\.install\(\)\.catch\(\(\)=>\{\}\)/);
});
