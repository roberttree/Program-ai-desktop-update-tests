import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { accountInputs, budgetObservation, cleanupFailureObservation, dismissVisibleProductTour, inNativeWindow, modelPointerTarget, openVisibleSyntheticSession, queueMessageObservation, syntheticQueuePrompts, validCallbackUrl, validSignInUrl } from "./native-account-queue.mjs";

const runId = "0ce7077a-fd9b-4f71-ab89-87029e523615";
const accountId = "12345678-1234-1234-1234-123456789abc";
const project = "/Users/runner/work/_temp/native-account-queue-a1B2c3/project";
const marker = `PAI_QUEUE_${accountId}`;

test("only the real dedicated two-field browser PKCE request is accepted, including when serialized into native bootstrap", () => {
  const url = `https://program-ai-desktop-api.vercel.app/auth/desktop?desktop_state=${"s".repeat(43)}&code_challenge=${"c".repeat(43)}`;
  assert.equal(validSignInUrl(url), true);
  assert.equal(Function(`return (${validSignInUrl.toString()})`)()(url), true);
  for (const invalid of [url.replace("program-ai-desktop-api.vercel.app", "platform.programai.co"), url.replace("/auth/desktop", "/other"),
    `${url}&desktop_state=${"x".repeat(43)}`, `${url}&next=/`, url + "#private", url.replace("https://", "https://person:secret@"),
    url.replace("desktop_state=", "%64esktop_state="), url.replace("code_challenge=", "token="), null]) {
    assert.equal(validSignInUrl(invalid), false);
  }
});

test("normal callback admits only the exact rendered ticket/state scheme and never a raw token or injected callback", () => {
  const callback = `program-ai://auth/callback?ticket=${"t".repeat(128)}&desktop_state=${"s".repeat(43)}`;
  assert.equal(validCallbackUrl(callback), true);
  for (const invalid of [callback + "&token=private", callback + "#private", callback.replace("ticket=", "code="),
    callback.replace("auth/callback", "other/callback"), callback.replace("program-ai://", "https://"),
    callback.replace("ticket=", "%74icket="), callback.replace("auth/", "auth:80/"), callback.replace("auth/", "user:secret@auth/")])
    assert.equal(validCallbackUrl(invalid), false);
});

function fakeCredentials(now = 1800000000000, arch = "x64") {
  const prefix = `PROGRAM_AI_NATIVE_1_0_10_${arch.toUpperCase()}`;
  const lease = { arch, runId, accountId, createdAtMs: now - 1000, fundingCredits: 40,
    useUntilMs: now + 60000, settings: { creditValueUsd: 0.03266667, providerCostMultiplier: 3.33333333, minimumGenerationCredits: 10 } };
  return { [`${prefix}_EMAIL`]: `desktop-native+${runId}-${arch}@example.invalid`, [`${prefix}_PASSWORD`]: "a".repeat(64), [`${prefix}_LEASE`]: JSON.stringify(lease) };
}

test("credential reads require the exact newly provisioned architecture/run, ordinary identity and unexpired lease", () => {
  const now = 1800000000000;
  assert.equal(accountInputs(fakeCredentials(now), "x64", now).accountId, accountId);
  assert.throws(() => accountInputs(fakeCredentials(now, "arm64"), "arm64", now), { code: "temporary_test_credentials_unavailable" });
  for (const changes of [
    { PROGRAM_AI_NATIVE_1_0_10_X64_EMAIL: "owner@example.invalid" },
    { PROGRAM_AI_NATIVE_1_0_10_X64_PASSWORD: "not-a-random-256-bit-password" },
    { PROGRAM_AI_NATIVE_1_0_10_X64_LEASE: "not JSON" },
  ]) assert.throws(() => accountInputs({ ...fakeCredentials(now), ...changes }, "x64", now), { code: "temporary_test_credentials_unavailable" });
  for (const changes of [{ runId: "9c86d0fb-b5ce-44fb-a61d-ac21cdf58948" }, { arch: "arm64" }, { useUntilMs: now - 1 }, { createdAtMs: now - 2700001 },
    { fundingCredits: 41 }, { settings: { minimumGenerationCredits: 0 } }, { accountId: "not-a-uuid" }]) {
    const env = fakeCredentials(now);
    env.PROGRAM_AI_NATIVE_1_0_10_X64_LEASE = JSON.stringify({ ...JSON.parse(env.PROGRAM_AI_NATIVE_1_0_10_X64_LEASE), ...changes });
    assert.throws(() => accountInputs(env, "x64", now), { code: "temporary_test_credentials_unavailable" });
  }
});

test("synthetic prompts use only the bounded disposable project, one sleep and one write, with exact LF canary bytes", () => {
  const prompts = syntheticQueuePrompts(project, marker);
  assert.match(prompts.first, /bash exactly once.*\/bin\/sleep 8/);
  assert.match(prompts.second, /write exactly once/); assert.ok(prompts.second.includes(`${project}/queue-result.txt`));
  assert.equal(prompts.expected, marker + "\n"); assert.equal(Buffer.byteLength(prompts.expected), 47);
  for (const invalid of [project.replace("/Users/runner", "/Users/owner"), project.replace("/_temp/", "/_temp/../"), project + "\n", "/Applications"])
    assert.throws(() => syntheticQueuePrompts(invalid, marker), { code: "synthetic_project_scope_invalid" });
});

test("native queue evidence requires actual saved sleep/write tool states and two final Done replies", () => {
  const filename = project + "/queue-result.txt";
  const tool = (name, input, status) => ({ type: "tool", tool: name, state: { status, input } });
  const assistant = (parts) => ({ info: { role: "assistant", time: { completed: 1 } }, parts });
  const messages = [assistant([tool("bash", { command: "/bin/sleep 8" }, "running")])];
  assert.equal(queueMessageObservation(messages, marker, filename).sleepRunning, true);
  messages[0].parts[0].state.status = "completed";
  messages.push(assistant([{ type: "text", text: "Done" }]), { info: { role: "user" }, parts: [{ type: "text", text: "Queue " + marker }] },
    assistant([tool("write", { filePath: filename }, "completed")]), assistant([{ type: "text", text: "Done" }]));
  assert.deepEqual(queueMessageObservation(messages, marker, filename), { sleepRunning: false, sleepCompleted: true, writeCompleted: true,
    otherTools: 0, finalDoneCount: 2, queuedUserSaved: true });
  messages.at(-1).parts[0].text = "Done.";
  assert.equal(queueMessageObservation(messages, marker, filename).finalDoneCount, 2);
  messages.at(-1).parts[0].text = "Done. Unexpected extra response";
  assert.equal(queueMessageObservation(messages, marker, filename).finalDoneCount, 1);
  messages.at(-1).parts[0].text = "Done.";
  assert.equal(queueMessageObservation(messages, marker, filename + ".other").writeCompleted, false);
  messages.push(assistant([tool("read", { filePath: "/private" }, "completed")]));
  const observed = queueMessageObservation(messages, marker, filename);
  assert.equal(observed.otherTools, 1); assert.doesNotMatch(JSON.stringify(observed), /\/private|PAI_QUEUE|command|filePath/);
});

test("native budget receipt is a fixed projection and cannot carry body, key, URL, path or raw failure data", () => {
  const value = budgetObservation({ attempted: 4, rejected: 0, maximumBodyBytes: 1024, maximumMessages: 10, maximumOutputTokens: 512,
    categories: ["private failure", "text_contract", "text_contract"], requestMutations: false, inferenceMocked: false, token: "private", raw: "/private" });
  assert.deepEqual(value.categories, ["text_contract"]); assert.equal(value.attempted, 4);
  assert.doesNotMatch(JSON.stringify(value), /private|token|\/|body"/);
  const invalid = budgetObservation({ attempted: 5, maximumOutputTokens: 513, requestMutations: true });
  assert.equal(invalid.attempted, null); assert.equal(invalid.maximumOutputTokens, null); assert.equal(invalid.requestMutations, "unverified");
});

test("cleanup diagnostics preserve a preceding setup failure and cannot leave a cleanup failure passed", () => {
  assert.deepEqual(cleanupFailureObservation({ status: "unverified", code: "browser_signature_unverified" }),
    { status: "unverified", code: "browser_signature_unverified", cleanupCode: "owned_cleanup_unverified" });
  assert.deepEqual(cleanupFailureObservation({ status: "failed", code: "native_queued_file_bytes_mismatch" }),
    { status: "failed", code: "native_queued_file_bytes_mismatch", cleanupCode: "owned_cleanup_unverified" });
  assert.deepEqual(cleanupFailureObservation({ status: "passed" }),
    { status: "unverified", code: "owned_cleanup_unverified", cleanupCode: "owned_cleanup_unverified" });
});

test("owned native debugger is detached after final observations but before process termination", async () => {
  const source = await readFile(new URL("./native-account-queue.mjs", import.meta.url), "utf8");
  const cleanup = source.slice(source.indexOf("const outcomes = await Promise.allSettled("));
  assert.ok(cleanup.indexOf("control.main?.close()") < cleanup.indexOf("await terminateOwned(control.expected.executable"));
  assert.ok(source.indexOf("receipt.nativeBudgetActive =") < source.indexOf("const outcomes = await Promise.allSettled("));
  assert.match(cleanup, /findOwnedPids\(control.expected.executable\)\)\.includes\(control.expected.pid\)/);
});

test("model pointer targets require the unique visible enabled hit-tested trigger or exact mini option", () => {
  let selector, hit;
  const rect = { left: 10, top: 20, width: 40, height: 30, right: 50, bottom: 50 };
  const trigger = { disabled: false, getBoundingClientRect: () => rect, hasAttribute: () => false,
    getAttribute: () => null, closest: () => null, contains: (node) => node === hit, click: () => assert.fail("DOM click forbidden") };
  const style = { display: "block", visibility: "visible", pointerEvents: "auto", opacity: "1" };
  const viewport = { innerWidth: 800, innerHeight: 600 };
  const doc = { visibilityState: "visible", querySelectorAll(value) { selector = value; return [trigger]; }, elementFromPoint: () => hit };
  const invoke = Function("document", "window", "getComputedStyle", "kind", `return (${modelPointerTarget.toString()})(kind)`);
  hit = trigger;
  assert.deepEqual(invoke(doc, viewport, () => style, "trigger"), { x: 30, y: 35, width: 800, height: 600 });
  assert.equal(selector, '[data-action="prompt-model"]');
  assert.deepEqual(invoke(doc, viewport, () => style, "option"), { x: 30, y: 35, width: 800, height: 600 });
  assert.match(selector, /data-option-key="openrouter:openai\/gpt-4\.1-mini"/);
  assert.match(selector, /data-provider-id="openrouter"\]\[data-model-id="openai\/gpt-4\.1-mini"/);
  assert.equal(invoke(doc, viewport, () => style, "arbitrary-selector"), false);
  assert.equal(invoke({ ...doc, querySelectorAll: () => [trigger, trigger] }, viewport, () => style, "trigger"), false);
  for (const changed of [{ disabled: true }, { closest: () => ({}) }, { hasAttribute: (name) => name === "data-disabled" },
    { getAttribute: () => "true" }, { getBoundingClientRect: () => ({ ...rect, width: 0 }) }])
    assert.equal(invoke({ ...doc, querySelectorAll: () => [{ ...trigger, ...changed }] }, viewport, () => style, "option"), false);
  for (const changed of [{ opacity: "0" }, { pointerEvents: "none" }, { visibility: "hidden" }, { display: "none" }])
    assert.equal(invoke(doc, viewport, () => ({ ...style, ...changed }), "trigger"), false);
  for (const changed of [{ innerWidth: 30 }, { innerHeight: 35 }, { innerWidth: Infinity }, { innerWidth: 16385 }])
    assert.equal(invoke(doc, { ...viewport, ...changed }, () => style, "trigger"), false);
  assert.equal(invoke({ ...doc, visibilityState: "hidden" }, viewport, () => style, "trigger"), false);
  assert.equal(invoke({ ...doc, elementFromPoint: () => ({}) }, viewport, () => style, "trigger"), false);
  assert.doesNotMatch(modelPointerTarget.toString(), /\.click\(|dispatchEvent|setModel|store/);
});

function nativePointerFixture() {
  const events = [], order = [];
  const expected = { pid: 123, executable: "/owned/Program AI Desktop", arch: "x64", resources: "/owned/Resources", version: "1.0.10" };
  let focused = false;
  const contents = { isDestroyed: () => false, getURL: () => "program-ai://renderer/index.html", getZoomFactor: () => 1,
    focus: () => { order.push("page_focus"); }, isFocused: () => focused,
    executeJavaScript: async () => { order.push("hit_test"); return { x: 30, y: 35, width: 800, height: 600 }; },
    sendInputEvent: (event) => { order.push(event.type); events.push(event); } };
  const window = { isDestroyed: () => false, isVisible: () => true, isFocused: () => focused, webContents: contents,
    focus: () => { order.push("window_focus"); queueMicrotask(() => { focused = true; }); } };
  const electron = { app: { isPackaged: true, getVersion: () => expected.version }, BrowserWindow: { getAllWindows: () => [window] } };
  const processFixture = { pid: expected.pid, execPath: expected.executable, arch: expected.arch, resourcesPath: expected.resources,
    getBuiltinModule: () => ({ createRequire: () => () => electron }) };
  const invoke = Function("process", "expected", `return (${inNativeWindow.toString()})(expected,"fixed-renderer-target",true)`);
  return { invoke: () => invoke(processFixture, expected), processFixture, expected, electron, window, contents, events, order };
}

test("owned native model pointer focuses before fresh hit test and sends full ordered same-point mouse sequence", async () => {
  const fixture = nativePointerFixture();
  assert.equal(await fixture.invoke(), true);
  assert.deepEqual(fixture.order, ["window_focus", "page_focus", "hit_test", "mouseMove", "mouseDown", "mouseUp"]);
  assert.deepEqual(fixture.events, [{ type: "mouseMove", x: 30, y: 35 },
    { type: "mouseDown", x: 30, y: 35, button: "left", clickCount: 1 },
    { type: "mouseUp", x: 30, y: 35, button: "left", clickCount: 1 }]);
  const failing = nativePointerFixture();
  failing.contents.sendInputEvent = (event) => { failing.events.push(event); if (event.type === "mouseDown") throw new Error("fixed_test_failure"); };
  await assert.rejects(failing.invoke(), /fixed_test_failure/);
  assert.deepEqual(failing.events.map((event) => event.type), ["mouseMove", "mouseDown", "mouseUp"]);
});

test("native model pointer refuses wrong process, duplicate renderer, focus loss and invalid point without sending events", async () => {
  const wrong = nativePointerFixture(); wrong.processFixture.pid++;
  await assert.rejects(wrong.invoke(), /owned_native_scope_required/);
  const duplicate = nativePointerFixture(); duplicate.electron.BrowserWindow.getAllWindows = () => [duplicate.window, duplicate.window];
  await assert.rejects(duplicate.invoke(), /owned_renderer_required/);
  const missing = nativePointerFixture(); missing.contents.getURL = () => "https://unowned.example/";
  await assert.rejects(missing.invoke(), /owned_renderer_required/);
  for (const point of [false, { x: -1, y: 35, width: 800, height: 600 }, { x: 800, y: 35, width: 800, height: 600 },
    { x: 30.5, y: 35, width: 800, height: 600 }, { x: 30, y: 35, width: 16385, height: 600 }]) {
    const fixture = nativePointerFixture(); fixture.contents.executeJavaScript = async () => point;
    assert.equal(await fixture.invoke(), false); assert.deepEqual(fixture.events, []);
  }
  const blurred = nativePointerFixture(); blurred.contents.executeJavaScript = async () => { blurred.window.isFocused = () => false; return { x: 30, y: 35, width: 800, height: 600 }; };
  assert.equal(await blurred.invoke(), false); assert.deepEqual(blurred.events, []);
  for (const fixture of [wrong, duplicate, missing]) assert.deepEqual(fixture.events, []);
});

test("fresh-account tour is dismissed only through its unique normal visible Skip tour button", () => {
  let clicked = 0;
  const button = { disabled: false, getBoundingClientRect: () => ({ width: 40, height: 30 }),
    getAttribute: () => null, closest: () => null, click: () => clicked++ };
  const tour = { getBoundingClientRect: button.getBoundingClientRect, querySelectorAll: (selector) => selector === '[data-testid="tour-skip"]' ? [button] : [] };
  const invoke = Function("document", `return (${dismissVisibleProductTour.toString()})()`);
  assert.equal(invoke({ querySelectorAll: () => [] }), "not_present");
  assert.equal(invoke({ querySelectorAll: () => [tour] }), "clicked");
  assert.equal(clicked, 1);
  assert.equal(invoke({ querySelectorAll: () => [tour, tour] }), "unverified");
  assert.equal(invoke({ querySelectorAll: () => [{ ...tour, querySelectorAll: () => [{ ...button, disabled: true }] }] }), "unverified");
  assert.equal(clicked, 1);
  assert.doesNotMatch(dismissVisibleProductTour.toString(), /store|localStorage|setSession|onDismiss/);
});

test("workspace opens through the actual unique saved-session button without document or router-state mutation", async () => {
  let clicked = 0, selector;
  const title = "Native account queue verification";
  const row = { disabled: false, getBoundingClientRect: () => ({ width: 80, height: 30 }),
    getAttribute: () => null, closest: () => null, querySelector: () => ({ textContent: title }), click: () => clicked++ };
  const invoke = Function("document", "title", `return (${openVisibleSyntheticSession.toString()})(title)`);
  assert.equal(invoke({ querySelectorAll(value) { selector = value; return [row]; } }, title), true);
  assert.equal(selector, "button.program-ai-session-row");
  assert.equal(clicked, 1);
  assert.equal(invoke({ querySelectorAll: () => [row, row] }, title), false);
  assert.equal(invoke({ querySelectorAll: () => [{ ...row, disabled: true }] }, title), false);
  assert.equal(invoke({ querySelectorAll: () => [row] }, "Customer session"), false);
  assert.equal(clicked, 1);
  const source = await readFile(new URL("./native-account-queue.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /location\.href\s*=|history\.pushState|history\.replaceState|PopStateEvent/);
  assert.match(source, /workspaceOpenedVia = "normal_sidebar_session_button"/);
});

test("live prototype proves exact public native CI and trust before spawning, installs budget before startup, and has no auth shortcut", async () => {
  const source = await readFile(new URL("./native-account-queue.mjs", import.meta.url), "utf8");
  const flow = source.slice(source.indexOf("export async function runNativeAccountQueue()"));
  assert.ok(flow.indexOf("await requireCiContext(pins)") < flow.indexOf("await ensureFreshHost(pins)"));
  assert.ok(flow.indexOf('check(context.arch === "x64"') < flow.indexOf("await ensureFreshHost(pins)"));
  assert.ok(flow.indexOf("await ensureFreshHost(pins)") < flow.indexOf("accountInputs(process.env"));
  assert.ok(flow.indexOf("await verifyApp(") < flow.indexOf("await startCandidate("));
  assert.match(source, /--inspect-brk=127\.0\.0\.1:/);
  assert.match(source, /PROGRAM_AI_EXPERIMENTAL_OUTPUT_TOKEN_MAX: "512"/);
  assert.match(source, /Reflect\.apply\(original, this, args\)/);
  assert.ok(source.indexOf('"Debugger.evaluateOnCallFrame"') < source.indexOf('"Debugger.resume"'));
  assert.match(source, /globalThis\.fetch = budget\.fetch/);
  assert.match(source, /window\.api\.programAICloudAuth\.signIn\(\)/);
  assert.match(source, /run\("\/usr\/bin\/open", \[callback\]/);
  assert.match(source, /budget\.attempted === 4 && budget\.rejected === 0/);
  assert.match(source, /file\.uid === process\.getuid\(\)/);
  assert.match(source, /queuedWhileToolRunning/);
  assert.doesNotMatch(source, /completeSignInCallback|setSession|exchangeCodeForSession|signInWithPassword|\.storeSet|\.storeGet|\.updater\.install|chat\/completions|--headless|--no-sandbox|ignore-certificate|tccutil|spctl[^\n]*--disable/);
  const children = source.match(/env: [^\n]+/g) ?? [];
  assert.ok(children.every((line) => !line.includes("process.env") && !line.includes("account")));
});

test("public integration uses reviewed relative inputs and owner-only free manual jobs with step-scoped temporary credentials", async () => {
  const source = await readFile(new URL("./native-account-queue.mjs", import.meta.url), "utf8");
  const workflow = await readFile(new URL("../.github/workflows/verify-native-account.yml", import.meta.url), "utf8");
  assert.doesNotMatch(source, /\/Users\/roberttree|\/private\/tmp\//);
  assert.match(source, /new URL\("\.\/candidate\.json", import\.meta\.url\)/);
  assert.match(source, /new URL\("\.\/native-budget\.mjs", import\.meta\.url\)/);
  for (const field of ["receipt.version", "receipt.sourceCommit", "receipt.candidatePinsSha256", "receipt.candidateZipSha256", "receipt.candidateAsarSha256", "receipt.candidateCdhash"])
    assert.ok(source.includes(field));
  for (const guard of ["workflow_dispatch:", "github.event.repository.private == false", "github.actor_id == '88110976'", "github.ref == 'refs/heads/main'", "contents: read", "persist-credentials: false"])
    assert.ok(workflow.includes(guard));
  assert.match(workflow, /runner: macos-15-intel\n/);
  assert.doesNotMatch(workflow, /arm64|ARM64|default: both|runner: macos-15\n/);
  assert.equal((workflow.match(/secrets\.PROGRAM_AI_NATIVE_1_0_10_X64_/g) ?? []).length, 3);
  assert.match(workflow, /default: x64/);
  const selection = source.slice(source.indexOf("async function selectMini("), source.indexOf("async function dismissProductTour("));
  assert.match(selection, /control\.modelPointer\("trigger"\)/);
  assert.match(selection, /control\.modelPointer\("option"\)/);
  assert.doesNotMatch(selection, /\.click\(|MouseEvent|PointerEvent|setModel|store|textContent\.includes/);
  assert.match(selection, /getAttribute\('data-provider-id'\)==='openrouter'&&n\.getAttribute\('data-model-id'\)==='openai\/gpt-4\.1-mini'/);
  assert.doesNotMatch(workflow, /schedule:|upload-artifact|actions\/cache|--prod|build:|apple|OPENROUTER_API_KEY|OPENAI_API_KEY|REPLICATE_API_TOKEN/);
  assert.ok(workflow.indexOf("secrets.PROGRAM_AI_NATIVE_") > workflow.indexOf("run: node ci/native-account-queue.mjs"));
});
