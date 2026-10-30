import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { makeNativeBudgetGuard } from "./native-budget.mjs";
import { VerificationFailure, applicationEnvironment, check, connectCdp, downloadPinned, ensureFreshHost, evaluate,
  extractZip, findOwnedPids, loadPins, requireCiContext, run, sha256File, terminateOwned, unusedPort, verifyApp, waitFor } from "./runtime.mjs";

const ORIGIN = "https://program-ai-desktop-api.vercel.app";
const PINS_FILE = fileURLToPath(new URL("./candidate.json", import.meta.url));
const PINS_SHA256 = "dcb5b68677bf51abfdcbb5c4b676d6941cacb6d71d5e13bc473190f8a81bbeb6";
const SOURCE_COMMIT = "35cd78e4f55e6fc5b15a8373e33dcf3958323415";
const GUARD_FILE = fileURLToPath(new URL("./native-budget.mjs", import.meta.url));
const GUARD_SHA256 = "830342bfb637170645430f2a853efe3e985040738a9c70bb14d2a525146e7d18";
const ACCOUNT_RUN = "9c86d0fb-b5ce-44fb-a61d-ac21cdf58948";
const CHROME = "/Applications/Google Chrome.app";
const CHROME_EXECUTABLE = `${CHROME}/Contents/MacOS/Google Chrome`;
const MARK = "program-ai-native-account-queue-verification";

export function validSignInUrl(value) {
  try {
    const url = new URL(value);
    return value.length <= 4096 && url.origin === "https://program-ai-desktop-api.vercel.app" && url.pathname === "/auth/desktop" && !url.username && !url.password && !url.hash &&
      url.searchParams.size === 2 && ["desktop_state", "code_challenge"].every((key) =>
        url.searchParams.getAll(key).length === 1 && /^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get(key) ?? "")) &&
      url.search === `?desktop_state=${url.searchParams.get("desktop_state")}&code_challenge=${url.searchParams.get("code_challenge")}`;
  } catch { return false; }
}

export function validCallbackUrl(value) {
  return typeof value === "string" && value.length <= 2170 &&
    /^program-ai:\/\/auth\/callback\?ticket=[A-Za-z0-9_-]{43,2048}&desktop_state=[A-Za-z0-9_-]{43}$/.test(value);
}

export function accountInputs(env, arch, now = Date.now()) {
  check(["arm64", "x64"].includes(arch), "temporary_test_credentials_unavailable");
  const prefix = `PROGRAM_AI_NATIVE_1_0_10_${arch.toUpperCase()}`;
  const email = env[`${prefix}_EMAIL`], password = env[`${prefix}_PASSWORD`];
  const encoded = env[`${prefix}_LEASE`]; let lease;
  try { if (typeof encoded === "string" && encoded.length <= 4096) lease = JSON.parse(encoded); } catch {}
  check(email === `desktop-native+${ACCOUNT_RUN}-${arch}@example.invalid` && typeof password === "string" && /^[a-f0-9]{64}$/.test(password) &&
    lease?.runId === ACCOUNT_RUN && lease.arch === arch && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(lease.accountId ?? "") &&
    Number.isSafeInteger(lease.createdAtMs) && lease.createdAtMs <= now + 1000 && lease.createdAtMs >= now - 2700000 &&
    Number.isSafeInteger(lease.useUntilMs) && lease.useUntilMs > now && lease.useUntilMs - now <= 2700000 && lease.fundingCredits === 40 &&
    Number.isFinite(lease.settings?.creditValueUsd) && lease.settings.creditValueUsd > 0 &&
    Number.isFinite(lease.settings?.providerCostMultiplier) && lease.settings.providerCostMultiplier > 0 && lease.settings?.minimumGenerationCredits === 10,
    "temporary_test_credentials_unavailable");
  return { email, password, accountId: lease.accountId, useUntilMs: lease.useUntilMs };
}

export function budgetObservation(value) {
  const output = {};
  for (const [key, maximum] of [["attempted", 4], ["rejected", 16], ["maximumBodyBytes", 65536], ["maximumMessages", 32], ["maximumOutputTokens", 512]])
    output[key] = Number.isSafeInteger(value?.[key]) && value[key] >= 0 && value[key] <= maximum ? value[key] : null;
  const allowed = ["unexpected_inference", "expired", "destination", "body_contract", "body_limit", "mode_contract", "text_contract", "output_limit", "provider_contract", "attempt_limit"];
  output.categories = Array.isArray(value?.categories) ? [...new Set(value.categories.filter((item) => allowed.includes(item)))].sort() : [];
  output.expired = value?.expired === true;
  output.requestMutations = value?.requestMutations === false ? false : "unverified";
  output.inferenceMocked = value?.inferenceMocked === false ? false : "unverified";
  return output;
}

export function cleanupFailureObservation(receipt) {
  return { status: receipt.status === "passed" ? "unverified" : receipt.status,
    code: receipt.code ?? "owned_cleanup_unverified", cleanupCode: "owned_cleanup_unverified" };
}

export function dismissVisibleProductTour() {
  const visible = (node) => node.getBoundingClientRect().width > 0 && node.getBoundingClientRect().height > 0;
  const tours = Array.from(document.querySelectorAll('[data-component="product-tour"]')).filter(visible);
  if (tours.length === 0) return "not_present";
  if (tours.length !== 1) return "unverified";
  const buttons = Array.from(tours[0].querySelectorAll('[data-testid="tour-skip"]'))
    .filter((node) => visible(node) && !node.disabled && node.getAttribute("aria-disabled") !== "true" && !node.closest("[inert]"));
  if (buttons.length !== 1) return "unverified";
  buttons[0].click();
  return "clicked";
}

export function clickVisibleModelTrigger() {
  const nodes = Array.from(document.querySelectorAll('[data-action="prompt-model"]'))
    .filter((node) => node.getBoundingClientRect().width > 0 && node.getBoundingClientRect().height > 0 &&
      !node.hasAttribute("disabled") && node.getAttribute("aria-disabled") !== "true" && !node.closest("[inert]"));
  if (nodes.length !== 1) return false;
  nodes[0].click();
  return true;
}

export function workspaceObservation() {
  const count = (selector) => Math.min(8, Array.from(document.querySelectorAll(selector))
    .filter((node) => node.getBoundingClientRect().width > 0 && node.getBoundingClientRect().height > 0).length);
  return { packagedIndexDocument: location.protocol === "program-ai:" && location.host === "renderer" &&
      ["/", "/index.html"].includes(location.pathname),
    newLayout: document.body.hasAttribute("data-new-layout"),
    visibleV2Composers: count('form[data-component="prompt-input-v2"]'),
    visibleEditors: count('[data-component="prompt-input"][contenteditable="true"]'),
    visibleModelTriggers: count('[data-action="prompt-model"]'),
    visibleTours: count('[data-component="product-tour"]'),
    visibleAlerts: count('[role="alert"]'),
    openingWorkspaceMessage: document.body.innerText.includes("Opening your workspace"),
    notFoundDocument: /^Not found\s*$/.test(document.body.innerText) };
}

export function openVisibleSyntheticSession(title) {
  if (title !== "Native account queue verification") return false;
  const rows = Array.from(document.querySelectorAll('button.program-ai-session-row'))
    .filter((node) => node.getBoundingClientRect().width > 0 && node.getBoundingClientRect().height > 0 &&
      !node.disabled && node.getAttribute("aria-disabled") !== "true" && !node.closest("[inert]") &&
      node.querySelector('.program-ai-sidebar-row-title')?.textContent.trim() === title);
  if (rows.length !== 1) return false;
  rows[0].click();
  return true;
}

export function syntheticQueuePrompts(project, marker) {
  check(/^\/Users\/runner\/[^\r\n'`$]*\/native-account-queue-[A-Za-z0-9]{6}\/project$/.test(project) &&
    path.normalize(project) === project && /^PAI_QUEUE_[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(marker), "synthetic_project_scope_invalid");
  return {
    first: "Native queue verification only. Call bash exactly once with command /bin/sleep 8. Do not read files, plan, search, delegate, or call another tool. After this tool completes reply exactly Done and stop.",
    second: `Native queue verification ${marker}. Call write exactly once to create ${project}/queue-result.txt with exactly these bytes: ${marker} followed by one LF newline. Do not read files, plan, search, delegate, or call another tool. After this tool completes reply exactly Done and stop.`,
    expected: `${marker}\n`,
  };
}

export function enterComposer(text) {
  const nodes = Array.from(document.querySelectorAll('[data-component="prompt-input"][contenteditable="true"],textarea[aria-label="Prompt"]'))
    .filter((node) => node.getBoundingClientRect().width > 0 && node.getBoundingClientRect().height > 0);
  if (nodes.length !== 1 || typeof text !== "string" || text.length > 2048) return false;
  const node = nodes[0]; node.focus();
  if (node instanceof HTMLTextAreaElement) Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set.call(node, text);
  else { node.textContent = text; const range = document.createRange(); range.selectNodeContents(node); range.collapse(false);
    const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); }
  node.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: text }));
  return (node instanceof HTMLTextAreaElement ? node.value : node.textContent) === text;
}

export function submitComposer() {
  const node = document.activeElement;
  if (!node?.matches('[data-component="prompt-input"][contenteditable="true"],textarea[aria-label="Prompt"]')) return false;
  node.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", bubbles: true, cancelable: true }));
  return true;
}

export function queueDomObservation(marker) {
  const rows = Array.from(document.querySelectorAll('[data-component="session-followup-row"]'));
  return { rows: Math.min(16, rows.length), markerRows: Math.min(16, rows.filter((node) => node.textContent.includes(marker)).length) };
}

export function queueMessageObservation(messages, marker, filename) {
  const list = Array.isArray(messages) ? messages : [];
  const parts = list.flatMap((message) => Array.isArray(message.parts) ? message.parts : []);
  const tools = parts.filter((part) => part.type === "tool");
  const sleep = tools.filter((part) => part.tool === "bash" && part.state?.input?.command === "/bin/sleep 8");
  const write = tools.filter((part) => part.tool === "write" && (part.state?.input?.filePath ?? part.state?.input?.path) === filename);
  const finals = list.filter((message) => message.info?.role === "assistant" && message.info?.time?.completed && !message.info?.error &&
    /^Done\.?$/.test(message.parts?.filter((part) => part.type === "text").map((part) => part.text).join("").trim() ?? ""));
  return { sleepRunning: sleep.some((part) => part.state?.status === "running"),
    sleepCompleted: sleep.length === 1 && sleep[0].state?.status === "completed",
    writeCompleted: write.length === 1 && write[0].state?.status === "completed",
    otherTools: Math.min(16, tools.length - sleep.length - write.length), finalDoneCount: Math.min(16, finals.length),
    queuedUserSaved: list.some((message) => message.info?.role === "user" && message.parts?.some((part) => part.type === "text" && part.text?.includes(marker))) };
}

function nativeBootstrap(expected, guardFactory, signInValidator) {
  const require = process.getBuiltinModule("module").createRequire(process.resourcesPath + "/app.asar/package.json");
  const electron = require("electron");
  if (process.pid !== expected.pid || process.execPath !== expected.executable || process.arch !== expected.arch ||
    process.resourcesPath !== expected.resources || !electron.app.isPackaged || electron.app.getVersion() !== expected.version ||
    process.env.PROGRAM_AI_EXPERIMENTAL_OUTPUT_TOKEN_MAX !== "512") throw new Error("owned_native_scope_required");
  const key = Symbol.for("program-ai-native-account-queue-verification");
  if (globalThis[key]) throw new Error("duplicate_native_budget_guard");
  if (!Number.isSafeInteger(expected.budgetExpiresAtMs) || expected.budgetExpiresAtMs <= Date.now() ||
    expected.budgetExpiresAtMs > Date.now() + 600000) throw new Error("owned_native_scope_required");
  const budget = guardFactory(globalThis.fetch, { expiresAtMs: expected.budgetExpiresAtMs });
  globalThis.fetch = budget.fetch;
  const observed = { budget, signInUrl: undefined };
  globalThis[key] = observed;
  const original = electron.shell.openExternal;
  electron.shell.openExternal = function(...args) {
    if (signInValidator(args[0])) observed.signInUrl = args[0];
    return Reflect.apply(original, this, args); // The real OS handoff is never suppressed or rewritten.
  };
  return globalThis.fetch === budget.fetch;
}

async function inNativeWindow(expected, expression) {
  const require = process.getBuiltinModule("module").createRequire(process.resourcesPath + "/app.asar/package.json");
  const electron = require("electron");
  if (process.pid !== expected.pid || process.execPath !== expected.executable || process.arch !== expected.arch ||
    process.resourcesPath !== expected.resources || !electron.app.isPackaged || electron.app.getVersion() !== expected.version) throw new Error("owned_native_scope_required");
  const windows = electron.BrowserWindow.getAllWindows().filter((window) => !window.isDestroyed() && window.isVisible() &&
    !window.webContents.isDestroyed() && window.webContents.getURL().startsWith("program-ai://renderer/"));
  if (windows.length !== 1) throw new Error("owned_renderer_required");
  return windows[0].webContents.executeJavaScript(expression, true);
}

async function startCandidate(app, arch, onSpawn, budgetExpiresAtMs) {
  const port = await unusedPort();
  const expected = { executable: app.executable, resources: path.resolve(app.executable, "../../Resources"), arch, version: app.version, budgetExpiresAtMs };
  const child = spawn(app.executable, [`--inspect-brk=127.0.0.1:${port}`], {
    env: { ...applicationEnvironment(), PROGRAM_AI_EXPERIMENTAL_OUTPUT_TOKEN_MAX: "512" }, stdio: "ignore",
  });
  child.on("error", () => {}); // Fixed caller failure only; never raw native errors.
  check(Number.isSafeInteger(child.pid) && child.pid > 1, "native_spawn_unverified");
  expected.pid = child.pid; onSpawn({ child, expected });
  const main = await connectCdp(port, child.pid, { targetType: "node", executable: app.executable, timeoutMs: 30000 });
  onSpawn({ child, expected, main });
  let frame;
  const stop = main.onEvent("Debugger.paused", (event) => { frame = event.callFrames?.[0]?.callFrameId; });
  await main.send("Debugger.enable"); await main.send("Runtime.runIfWaitingForDebugger");
  await waitFor(() => typeof frame === "string" && frame.length <= 1024, { timeoutMs: 20000, code: "native_bootstrap_pause_unverified" });
  const guard = await main.send("Debugger.evaluateOnCallFrame", { callFrameId: frame, returnByValue: true, silent: true,
    expression: `(${nativeBootstrap.toString()})(${JSON.stringify(expected)},(${makeNativeBudgetGuard.toString()}),(${validSignInUrl.toString()}))` });
  check(!guard.exceptionDetails && guard.result?.value === true, "native_budget_bootstrap_unverified");
  stop(); await main.send("Debugger.resume"); await main.send("Debugger.disable");
  return { child, main, expected, window: (expression, timeout = 30000) => evaluate(main,
    `(${inNativeWindow.toString()})(${JSON.stringify(expected)},${JSON.stringify(expression)})`, timeout) };
}

async function startAuthBrowser(root, onSpawn) {
  await run("/usr/bin/codesign", ["--verify", "--deep", "--strict", CHROME], { code: "browser_signature_unverified" });
  await run("/usr/sbin/spctl", ["--assess", "--type", "execute", CHROME], { code: "browser_gatekeeper_unverified" });
  const info = JSON.parse((await run("/usr/bin/plutil", ["-convert", "json", "-o", "-", `${CHROME}/Contents/Info.plist`])).stdout);
  check(info.CFBundleIdentifier === "com.google.Chrome" && info.CFBundleExecutable === "Google Chrome", "browser_identity_unverified");
  const profile = path.join(root, "auth-browser"); await mkdir(profile, { mode: 0o700 });
  const port = await unusedPort();
  const child = spawn(CHROME_EXECUTABLE, [`--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, "--remote-debugging-address=127.0.0.1",
    "--no-first-run", "--no-default-browser-check", "about:blank"], { env: applicationEnvironment(), stdio: "ignore" });
  child.on("error", () => {});
  check(Number.isSafeInteger(child.pid) && child.pid > 1, "browser_spawn_unverified");
  onSpawn({ child });
  const page = await connectCdp(port, child.pid, { executable: CHROME_EXECUTABLE, timeoutMs: 30000 });
  return { child, page };
}

async function sidecarConnection(control) {
  const value = await control.window("window.api.awaitInitialization()", 90000);
  const url = new URL(value.url);
  check(url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) && !url.username && !url.password &&
    url.pathname === "/" && !url.search && !url.hash && typeof value.username === "string" && typeof value.password === "string", "native_sidecar_scope_unverified");
  return { origin: url.origin, authorization: `Basic ${Buffer.from(value.username + ":" + value.password).toString("base64")}` };
}

async function sidecarRequest(connection, route, project, body) {
  check(/^\/session(?:\/[A-Za-z0-9_-]{8,128}\/message)?$/.test(route), "native_sidecar_route_rejected");
  const url = new URL(route, connection.origin); url.searchParams.set("directory", project);
  const response = await fetch(url, { method: body ? "POST" : "GET", redirect: "error", signal: AbortSignal.timeout(10000),
    headers: { Authorization: connection.authorization, ...(body ? { "Content-Type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  check(response.ok, "native_sidecar_operation_unverified");
  const text = await response.text(); check(text.length < 2 * 1024 * 1024, "native_sidecar_response_limit");
  return JSON.parse(text);
}

async function selectMini(control) {
  check(await control.window(`(${clickVisibleModelTrigger.toString()})()`), "native_model_control_unavailable");
  await waitFor(() => control.window(`(()=>{const nodes=Array.from(document.querySelectorAll('[data-composer-menu="true"] input, [role="dialog"] [data-slot="list-search-input"], [role="dialog"] input[type="search"]')).filter(x=>x.getBoundingClientRect().height>0);if(nodes.length!==1)return false;const input=nodes[0];Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'openai/gpt-4.1-mini');input.dispatchEvent(new Event('input',{bubbles:true}));return true})()`), { timeoutMs: 30000, code: "native_model_search_unavailable" });
  await waitFor(() => control.window(`(()=>{const nodes=Array.from(document.querySelectorAll('[data-option-key="openrouter:openai/gpt-4.1-mini"],[data-key="openrouter:openai/gpt-4.1-mini"],[role="dialog"] button[data-provider-id="openrouter"][data-model-id="openai/gpt-4.1-mini"]')).filter(x=>x.getBoundingClientRect().height>0&&!x.hasAttribute('data-disabled')&&!x.disabled&&x.getAttribute('aria-disabled')!=='true');if(nodes.length!==1)return false;nodes[0].click();return true})()`), { timeoutMs: 30000, code: "native_exact_model_unavailable" });
  await waitFor(() => control.window(`(()=>{const nodes=Array.from(document.querySelectorAll('[data-action="prompt-model"]')).filter(x=>x.getBoundingClientRect().height>0);if(nodes.length!==1)return false;const n=nodes[0];return n.hasAttribute('data-model-id')?n.getAttribute('data-provider-id')==='openrouter'&&n.getAttribute('data-model-id')==='openai/gpt-4.1-mini':n.textContent.includes('GPT-4.1 Mini')})()`), { timeoutMs: 10000, code: "native_selected_model_unverified" });
}

async function dismissProductTour(control) {
  const outcome = await control.window(`(${dismissVisibleProductTour.toString()})()`);
  check(["clicked", "not_present"].includes(outcome), "native_product_tour_control_unverified");
  if (outcome === "clicked") await waitFor(() => control.window("!Array.from(document.querySelectorAll('[data-component=product-tour]')).some(n=>n.getBoundingClientRect().width>0&&n.getBoundingClientRect().height>0)"),
    { timeoutMs: 10000, code: "native_product_tour_dismissal_unverified" });
  return outcome === "clicked";
}

async function normalWebSignIn(control, browser, account) {
  check(await control.window("window.api.programAICloudAuth.getState().then(s=>s.status==='signed_out')"), "fresh_signed_out_unverified");
  await control.window("window.api.programAICloudAuth.signIn().then(()=>true)");
  const url = await waitFor(async () => {
    const observed = await evaluate(control.main, `globalThis[Symbol.for(${JSON.stringify(MARK)})]?.signInUrl`);
    return validSignInUrl(observed) ? observed : false;
  }, { timeoutMs: 30000, code: "actual_browser_sign_in_url_unverified" });
  await browser.page.send("Page.navigate", { url });
  await waitFor(() => browser.page.evaluate(`location.origin===${JSON.stringify(ORIGIN)}&&location.pathname==='/auth/desktop'&&!!document.querySelector('form[action="/auth/desktop/sign-in"][method="post"]')`), { timeoutMs: 30000, code: "normal_web_form_unavailable" });
  check(Date.now() < account.useUntilMs, "temporary_test_credentials_expired");
  const filled = await browser.page.evaluate(`(()=>{if(location.origin!==${JSON.stringify(ORIGIN)}||location.pathname!=='/auth/desktop')return false;const form=document.querySelector('form[action="/auth/desktop/sign-in"][method="post"]');if(!form)return false;const email=form.querySelector('input[name="email"][type="email"]'),password=form.querySelector('input[name="password"][type="password"]'),csrf=form.querySelector('input[name="csrf"]');if(!email||!password||!/^[A-Za-z0-9_-]{43}$/.test(csrf?.value??''))return false;const input=${JSON.stringify({ email: account.email, password: account.password })};for(const [node,value]of[[email,input.email],[password,input.password]]){Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(node,value);node.dispatchEvent(new Event('input',{bubbles:true}));node.dispatchEvent(new Event('change',{bubbles:true}));}form.querySelector('button[type="submit"]').click();return true})()`);
  check(filled === true, "normal_web_form_unverified");
  const callback = await waitFor(async () => {
    const href = await browser.page.evaluate(`(()=>{if(location.origin!==${JSON.stringify(ORIGIN)}||!['/auth/desktop','/auth/desktop/sign-in'].includes(location.pathname))return null;const links=Array.from(document.querySelectorAll('a.primary')).filter(a=>a.textContent.trim()==='Open Program AI Desktop');return links.length===1?links[0].href:null})()`);
    return validCallbackUrl(href) ? href : false;
  }, { timeoutMs: 30000, code: "actual_web_callback_unverified" });
  // This is the exact server-rendered, RAM-only callback, not a fabricated code
  // or controller call. Ordinary LaunchServices dispatch performs native PKCE.
  await run("/usr/bin/open", [callback], { env: applicationEnvironment(), maxBytes: 4096, code: "normal_callback_dispatch_unverified" });
  await waitFor(() => control.window(`window.api.programAICloudAuth.getState().then(s=>s.status==='signed_in'&&s.user?.id===${JSON.stringify(account.accountId)}&&s.user?.email?.toLowerCase()===${JSON.stringify(account.email.toLowerCase())})`), { timeoutMs: 90000, code: "native_expected_account_unverified" });
  await waitFor(() => control.window("window.api.programAIManagedService.getState().then(s=>s.status==='ready')"), { timeoutMs: 90000, code: "native_account_service_unverified" });
}

export async function runNativeAccountQueue() {
  const receipt = { schemaVersion: 1, flow: "native_account_queue", status: "unverified", phase: "preflight",
    installerAcceptance: false, chromeProtocolConfirmation: "not_claimed", editorDraftRestoration: "not_claimed", ledger: "not_checked", cleanupRequired: true };
  let control, browser, guarded = false;
  try {
    check(await sha256File(PINS_FILE) === PINS_SHA256, "candidate_metadata_hash_mismatch");
    check(await sha256File(GUARD_FILE) === GUARD_SHA256, "native_budget_source_hash_mismatch");
    const pins = await loadPins(PINS_FILE); check(pins.source.commit === SOURCE_COMMIT, "candidate_source_mismatch");
    const context = await requireCiContext(pins); guarded = true; receipt.arch = context.arch; receipt.version = pins.version; receipt.sourceCommit = SOURCE_COMMIT; receipt.candidatePinsSha256 = PINS_SHA256;
    await ensureFreshHost(pins);
    const account = accountInputs(process.env, context.arch); // Never passed to either child environment.
    const runnerTemp = await realpath(process.env.RUNNER_TEMP ?? "");
    const info = await lstat(runnerTemp);
    check(runnerTemp.startsWith("/Users/runner/") && info.isDirectory() && info.uid === process.getuid(), "runner_temporary_unverified");
    const root = await mkdtemp(path.join(runnerTemp, "native-account-queue-")), project = path.join(root, "project");
    await mkdir(project, { mode: 0o700 });
    receipt.phase = "candidate_verify";
    const artifact = pins.artifacts[context.arch].zip; receipt.candidateZipSha256 = artifact.sha256;
    const zip = await downloadPinned(artifact, path.join(root, artifact.name));
    const app = await verifyApp(await extractZip(zip, path.join(root, "candidate")), { pins, arch: context.arch });
    receipt.candidateAsarSha256 = app.asarSha256; receipt.candidateCdhash = app.cdhash;
    receipt.phase = "native_bootstrap"; control = await startCandidate(app, context.arch, (owned) => { control = owned; }, Math.min(Date.now() + 600000, account.useUntilMs));
    await waitFor(() => control.window("!!window.api?.programAICloudAuth?.signIn&&!!window.api?.awaitInitialization"), { timeoutMs: 90000, code: "native_preload_unavailable" });
    receipt.phase = "browser_preflight"; browser = await startAuthBrowser(root, (owned) => { browser = owned; });
    receipt.phase = "normal_account_sign_in"; await normalWebSignIn(control, browser, account); receipt.accountConnected = true;
    receipt.phase = "product_tour"; receipt.tourDismissed = await dismissProductTour(control);
    receipt.phase = "sidecar_ready"; const connection = await sidecarConnection(control);
    receipt.phase = "session_create"; const session = await sidecarRequest(connection, "/session", project, { title: "Native account queue verification" });
    check(typeof session.id === "string" && /^[A-Za-z0-9_-]{8,128}$/.test(session.id), "native_session_unverified");
    // The packaged renderer uses MemoryRouter. Open the actual saved session
    // button, which registers its project and selects its tab through normal UI.
    // A document-level location change would instead request a nonexistent file.
    receipt.phase = "workspace_open";
    await waitFor(() => control.window(`(${openVisibleSyntheticSession.toString()})(${JSON.stringify("Native account queue verification")})`),
      { timeoutMs: 60000, code: "native_session_row_unavailable" });
    receipt.workspaceOpenedVia = "normal_sidebar_session_button";
    await waitFor(() => control.window("(()=>{const editors=Array.from(document.querySelectorAll('[data-component=prompt-input][contenteditable=true]')).filter(n=>n.getBoundingClientRect().width>0&&n.getBoundingClientRect().height>0);const models=Array.from(document.querySelectorAll('[data-action=prompt-model]')).filter(n=>n.getBoundingClientRect().width>0&&n.getBoundingClientRect().height>0);return editors.length===1&&models.length===1})()"), { timeoutMs: 90000, code: "native_composer_unavailable" });
    receipt.phase = "workspace_tour"; receipt.tourDismissed = await dismissProductTour(control) || receipt.tourDismissed;
    receipt.phase = "model_select"; await selectMini(control);
    receipt.modelSelected = "openai/gpt-4.1-mini";
    check(Date.now() < account.useUntilMs, "temporary_test_credentials_expired");
    check(await evaluate(control.main, `(()=>{const s=globalThis[Symbol.for(${JSON.stringify(MARK)})];return !!s&&globalThis.fetch===s.budget.fetch&&s.budget.read().attempted===0&&s.budget.read().rejected===0})()`), "native_budget_not_active");
    const marker = `PAI_QUEUE_${randomUUID()}`, prompts = syntheticQueuePrompts(project, marker), filename = path.join(project, "queue-result.txt");
    const observeMessages = async () => queueMessageObservation(await sidecarRequest(connection, `/session/${session.id}/message`, project), marker, filename);
    receipt.phase = "first_prompt";
    check(await control.window(`(${enterComposer.toString()})(${JSON.stringify(prompts.first)})`), "native_first_prompt_input_unverified");
    check(await control.window(`(${submitComposer.toString()})()`), "native_first_prompt_submission_unverified");
    await waitFor(async () => (await observeMessages()).sleepRunning, { timeoutMs: 60000, code: "native_sleep_tool_unverified", intervalMs: 150 });
    receipt.phase = "queue_followup";
    check(await control.window(`(${enterComposer.toString()})(${JSON.stringify(prompts.second)})`), "native_queued_prompt_input_unverified");
    check(await control.window(`(${submitComposer.toString()})()`), "native_queued_prompt_submission_unverified");
    const queued = await waitFor(async () => {
      const dom = await control.window(`(${queueDomObservation.toString()})(${JSON.stringify(marker)})`);
      const messages = await observeMessages();
      const absent = await lstat(filename).then(() => false, (error) => error.code === "ENOENT");
      return dom.rows === 1 && dom.markerRows === 1 && messages.sleepRunning && absent;
    }, { timeoutMs: 7000, code: "native_busy_queue_unverified", intervalMs: 100 });
    receipt.queuedWhileToolRunning = queued === true;
    receipt.phase = "queue_drain";
    const completed = await waitFor(async () => {
      const value = await observeMessages();
      return value.sleepCompleted && value.writeCompleted && value.otherTools === 0 && value.finalDoneCount === 2 && value.queuedUserSaved ? value : false;
    }, { timeoutMs: 120000, code: "native_queue_drain_unverified" });
    const file = await lstat(filename);
    check(file.isFile() && !file.isSymbolicLink() && file.uid === process.getuid() && file.size === Buffer.byteLength(prompts.expected) &&
      await realpath(filename) === filename && (await readFile(filename, "utf8")) === prompts.expected, "native_queued_file_bytes_mismatch", "failed");
    const dom = await control.window(`(${queueDomObservation.toString()})(${JSON.stringify(marker)})`);
    check(dom.rows === 0, "native_queue_not_empty");
    check(await evaluate(control.main, `(()=>{const s=globalThis[Symbol.for(${JSON.stringify(MARK)})];return !!s&&globalThis.fetch===s.budget.fetch})()`), "native_budget_not_active");
    const budget = budgetObservation(await evaluate(control.main, `globalThis[Symbol.for(${JSON.stringify(MARK)})].budget.read()`));
    check(budget.attempted === 4 && budget.rejected === 0 && Number.isSafeInteger(budget.maximumOutputTokens) && budget.maximumOutputTokens >= 1 &&
      Number.isSafeInteger(budget.maximumBodyBytes) && budget.maximumBodyBytes >= 1 && Number.isSafeInteger(budget.maximumMessages) && budget.maximumMessages >= 1 &&
      budget.requestMutations === false && budget.inferenceMocked === false, "native_budget_acceptance_unverified");
    receipt.budget = budget; receipt.queueDrained = true; receipt.exactFileBytes = true; receipt.finalDoneCount = completed.finalDoneCount;
    receipt.status = "passed"; receipt.phase = "completed";
  } catch (error) {
    receipt.status = error instanceof VerificationFailure ? error.kind : "unverified";
    receipt.code = error instanceof VerificationFailure ? error.code : "prototype_operation_unverified";
  } finally {
    if (guarded) {
      if (control?.main) {
        if (receipt.status !== "passed" && control.window) receipt.workspace = await control.window(`(${workspaceObservation.toString()})()`, 3000).catch(() => ({ unavailable: true }));
        const finalBudget = await evaluate(control.main, `(()=>{const s=globalThis[Symbol.for(${JSON.stringify(MARK)})];return s?{active:globalThis.fetch===s.budget.fetch,budget:s.budget.read()}:null})()`, 2000).catch(() => null);
        receipt.nativeBudgetActive = finalBudget?.active === true;
        if (finalBudget?.budget) receipt.budget = budgetObservation(finalBudget.budget);
        if (receipt.status === "passed" && !receipt.nativeBudgetActive) { receipt.status = "unverified"; receipt.code = "native_budget_not_active"; }
      }
      const outcomes = await Promise.allSettled([
        (async () => { if (!control) return;
          if (control.window) receipt.accountSignOut = await control.window("window.api.programAICloudAuth.signOut().then(()=>window.api.programAICloudAuth.getState()).then(s=>s.status==='signed_out')").then((value) => value === true ? "confirmed" : "unverified", () => "unverified");
          // A live Node inspector can keep an otherwise-terminated process
          // waiting for debugger disconnect. Finish observations, then detach
          // before terminating only our already-attested native process.
          control.main?.close();
          if ((await findOwnedPids(control.expected.executable)).includes(control.expected.pid)) await terminateOwned(control.expected.executable, control.expected.pid);
        })(),
        (async () => { if (!browser) return; browser.page?.close();
          if ((await findOwnedPids(CHROME_EXECUTABLE)).includes(browser.child.pid)) await terminateOwned(CHROME_EXECUTABLE, browser.child.pid);
        })(),
      ]);
      if (outcomes.some((outcome) => outcome.status === "rejected")) Object.assign(receipt, cleanupFailureObservation(receipt));
    }
    console.log(JSON.stringify(receipt)); // No raw exceptions, credentials, callback URLs, paths, PIDs or app output.
  }
  return receipt;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await runNativeAccountQueue().then((result) => { if (result.status !== "passed") process.exitCode = 1; });
}
