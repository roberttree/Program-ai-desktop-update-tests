import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  SCENARIOS, bootstrapMain, byteRange, caseReceipt, evaluatePaused, loopbackUrl, metadata, parseScenario, pausedCallFrame,
  payloadChunk, rejectionOutcome, syntheticShellCommand, updaterObservation, validatePreservation,
} from "./verify-update.mjs";

const traffic = () => ({ metadata: 1, zip: 1, sent: 100, expectedBytes: 100, corrupted: 1, interrupted: 1 });
const state = () => ({ marker: "synthetic\n", store: "unsent canary", session: "session_synthetic_1",
  title: "Synthetic shell chat", messages: ["message_1", "message_2"], signedOut: true });

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

test("wrong-signature rejection requires complete fault payload and actual signature category", () => {
  assert.equal(rejectionOutcome("signature", { status: "error", errorClass: "signature" }, traffic()), "passed");
  assert.equal(rejectionOutcome("signature", { status: "ready" }, traffic()), "failed");
  assert.equal(rejectionOutcome("signature", { status: "error", errorClass: "checksum" }, traffic()), "unverified");
  assert.equal(rejectionOutcome("signature", { status: "error", errorClass: "signature" }, { ...traffic(), sent: 1 }), "unverified");
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
  assert.equal(syntheticShellCommand(marker), `printf '%s' '${marker}' > update-canary.txt`);
  for (const value of ["secret", marker + "x", "Public native update canary ';rm -rf /\n"]) {
    assert.throws(() => syntheticShellCommand(value), { code: "synthetic_marker_invalid" });
  }
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
  assert.doesNotMatch(source, /console\.(?:error|log)\(error|JSON\.stringify\(connection|Authorization.*console/);
});
