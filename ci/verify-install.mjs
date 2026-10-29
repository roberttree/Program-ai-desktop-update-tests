import { lstat, mkdir, mkdtemp, realpath, rename } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  VerificationFailure, applicationEnvironment, approvedRedirect, assertAbsent, check, connectCdp, connectWebSocket, downloadPinned,
  emitReceipt, ensureFreshHost, extractZip, findOwnedPids, launchObservation, loadPins, loopbackWebSocket,
  quarantineRecord, requireCiContext, run, sha256File, terminateOwned, unusedPort, verifyApp, verifyDmg, verifyListener, waitFor,
} from "./runtime.mjs";

const CHROME = "/Applications/Google Chrome.app";
const CHROME_EXECUTABLE = `${CHROME}/Contents/MacOS/Google Chrome`;
const INSTALLED_APP = "/Applications/Program AI Desktop.app";

export function normalOpenDialog({ text, buttons }, application) {
  return ["Google Chrome", "Program AI Desktop"].includes(application) && Array.isArray(text) && Array.isArray(buttons) &&
    text.length > 0 && text.length <= 8 && text.every((item) => typeof item === "string" && item.length <= 2048) &&
    buttons.length === 2 && buttons.includes("Open") && buttons.includes("Cancel") &&
    text.some((item) => item.includes(application)) && /downloaded from the internet/i.test(text.join(" ")) &&
    /are you sure.*open/i.test(text.join(" ")) &&
    !/damaged|malware|cannot be opened|can.t be opened|unidentified|open anyway|trash|bin/i.test(text.join(" "));
}

export function validDownloadEvent(event, artifact) {
  if (!event || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(event.guid ?? "") || event.suggestedFilename !== artifact.name) return false;
  try { approvedRedirect(event.url); return true; } catch { return false; }
}

export function sameBrowserFile(before, after, quarantineBefore, quarantineAfter) {
  return before.isFile() && after.isFile() && !before.isSymbolicLink() && !after.isSymbolicLink() &&
    before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.size > 0 &&
    quarantineBefore === quarantineAfter;
}

async function approveNormalOpen(application) {
  // Only the ordinary, exact-name Open/Cancel confirmation is eligible. This
  // does not click "Open Anyway", grant TCC, or change a security setting.
  const script = `(() => {
    const agent = Application("System Events").applicationProcesses.byName("CoreServicesUIAgent");
    if (!agent.exists()) return false;
    const windows = agent.windows();
    if (windows.length !== 1) return false;
    const text = [], buttons = [], open = []; let visited = 0;
    const visit = (node, depth) => {
      if (++visited > 256 || depth > 10) throw new Error("bounded");
      const role = node.role();
      if (role === "AXStaticText") text.push(node.value());
      if (role === "AXButton") { buttons.push(node.name()); if (node.name() === "Open") open.push(node); }
      node.uiElements().forEach(child => visit(child, depth + 1));
    };
    visit(windows[0], 0);
    if (!(${normalOpenDialog.toString()})({text, buttons}, ${JSON.stringify(application)}) || open.length !== 1) return false;
    open[0].click(); return true;
  })()`;
  const result = await run("/usr/bin/osascript", ["-l", "JavaScript", "-e", script], { timeoutMs: 10000, allowFailure: true });
  return result.exitCode === 0 && result.stdout.trim() === "true";
}

export function launchFailureCode(value) {
  const observation = launchObservation(value);
  const suffix = observation.openStatus === "failed" ? "open_failed" : observation.pidCount === 0 ? "process_missing" :
    observation.pidCount > 1 ? "process_ambiguous" : "listener_unverified";
  return `${observation.context}_${suffix}`;
}

async function ownedDiagnosticPort(executable, port, application, observation, observe) {
  try {
    return await waitFor(async () => {
      const pids = await findOwnedPids(executable);
      observation.pidCount = Math.min(pids.length, 2);
      if (pids.length !== 1) {
        observation.listener = "not_checked";
        observation.dialogApproved = await approveNormalOpen(application) || observation.dialogApproved;
        observe(observation); return false;
      }
      observation.listener = "unverified"; observe(observation);
      await verifyListener(port, pids[0], executable);
      observation.listener = "ready"; observe(observation);
      return pids[0];
    }, { timeoutMs: 90000, code: "normal_native_launch_unverified" });
  } catch (error) {
    if (error instanceof VerificationFailure && error.kind === "failed") throw error;
    throw new VerificationFailure("unverified", launchFailureCode(observation));
  }
}

function opening(result, observation, observe) {
  observation.openStatus = result.exitCode === 0 ? "succeeded" : "failed";
  observation.openExitCode = Number.isInteger(result.exitCode) && result.exitCode >= 0 && result.exitCode <= 255 ? result.exitCode : null;
  observation.openTimedOut = result.timedOut === true;
  observe(observation);
  return result.exitCode === 0;
}

async function browserDownload(root, downloads, artifact, onLaunch, observePhase, observeLaunch, observeGui) {
  observePhase("browser_preflight");
  const info = JSON.parse((await run("/usr/bin/plutil", ["-convert", "json", "-o", "-", `${CHROME}/Contents/Info.plist`])).stdout);
  check(info.CFBundleIdentifier === "com.google.Chrome" && info.LSFileQuarantineEnabled === true,
    "browser_quarantine_capability_unverified");
  await run("/usr/bin/codesign", ["--verify", "--deep", "--strict", CHROME], { code: "browser_signature_unverified" });
  await run("/usr/sbin/spctl", ["--assess", "--type", "execute", CHROME], { code: "browser_trust_unverified" });
  check((await findOwnedPids(CHROME_EXECUTABLE)).length === 0, "preexisting_browser_process");
  // Read-only capability facts on the guarded disposable CI host. No GUI/TCC
  // settings are changed, and no process identifiers or command output escape.
  const consoleUser = await run("/usr/bin/stat", ["-f", "%Su", "/dev/console"], { allowFailure: true, timeoutMs: 10000, maxBytes: 4096 });
  const gui = await run("/bin/launchctl", ["print", `gui/${process.getuid()}`], { allowFailure: true, timeoutMs: 10000, maxBytes: 4 * 1024 * 1024 });
  observeGui({ consoleUserIsRunner: consoleUser.exitCode === 0 && consoleUser.stdout.trim() === "runner",
    guiBootstrapAvailable: gui.exitCode === 0,
    guiBootstrapExitCode: Number.isInteger(gui.exitCode) && gui.exitCode >= 0 && gui.exitCode <= 255 ? gui.exitCode : null });
  const port = await unusedPort();
  const started = Date.now();
  const observation = { context: "browser", pidCount: 0, listener: "not_checked", openStatus: "pending", openExitCode: null,
    openTimedOut: false, dialogApproved: false };
  observePhase("browser_launch"); observeLaunch(observation);
  onLaunch();
  const launched = run("/usr/bin/open", ["-n", "-a", CHROME, "--args", `--user-data-dir=${path.join(root, "browser-profile")}`,
    `--remote-debugging-port=${port}`, "--remote-debugging-address=127.0.0.1", "--no-first-run", "--no-default-browser-check", "about:blank"],
    { env: applicationEnvironment(), code: "headed_browser_launch_unverified", allowFailure: true })
    .then((result) => opening(result, observation, observeLaunch), () => opening({ exitCode: null, timedOut: false }, observation, observeLaunch));
  const pid = await ownedDiagnosticPort(CHROME_EXECUTABLE, port, "Google Chrome", observation, observeLaunch);
  check(await launched, "headed_browser_launch_unverified");
  observePhase("browser_connect");
  const page = await connectCdp(port, pid, { executable: CHROME_EXECUTABLE });
  const version = await fetch(`http://127.0.0.1:${port}/json/version`, { redirect: "error", signal: AbortSignal.timeout(5000) });
  const metadata = await version.json();
  const endpoint = loopbackWebSocket(metadata.webSocketDebuggerUrl);
  check(endpoint.port === String(port), "diagnostic_owner_invalid");
  const browser = await connectWebSocket(endpoint.href);
  let begun;
  let completed = false;
  const stopBegin = browser.onEvent("Browser.downloadWillBegin", (event) => { if (validDownloadEvent(event, artifact)) begun = event; });
  const stopProgress = browser.onEvent("Browser.downloadProgress", (event) => {
    if (begun && event.guid === begun.guid && event.state === "completed") completed = true;
  });
  try {
    await browser.send("Browser.setDownloadBehavior", { behavior: "allowAndName", downloadPath: downloads, eventsEnabled: true });
    await page.send("Page.enable");
    const url = new URL(artifact.url);
    const release = url.pathname.replace(/\/download\//, "/expanded_assets/").replace(/\/[^/]+$/, "");
    observePhase("browser_navigation");
    await page.send("Page.navigate", { url: `https://github.com${release}` });
    await waitFor(async () => page.evaluate(`(() => {
      const items = Array.from(document.querySelectorAll('a[href]')).filter(a => a.getAttribute('href') === ${JSON.stringify(url.pathname)});
      if (items.length !== 1) return false;
      items[0].click(); return true;
    })()`), { timeoutMs: 60000, code: "browser_asset_link_unverified" });
    observePhase("browser_download");
    await waitFor(() => completed && begun, { timeoutMs: 10 * 60 * 1000, code: "browser_download_unverified" });
    const original = path.join(downloads, begun.guid);
    check((await realpath(original)) === original, "browser_download_path_invalid");
    const before = await lstat(original);
    check(before.isFile() && !before.isSymbolicLink() && before.size === artifact.bytes &&
      await sha256File(original) === artifact.sha256, "browser_artifact_mismatch", "failed");
    const quarantine = (await run("/usr/bin/xattr", ["-p", "com.apple.quarantine", original], { code: "genuine_browser_quarantine_unverified" })).stdout.trim();
    quarantineRecord(quarantine, started);
    const named = path.join(downloads, artifact.name);
    await assertAbsent(named);
    await rename(original, named);
    const after = await lstat(named);
    const renamedQuarantine = (await run("/usr/bin/xattr", ["-p", "com.apple.quarantine", named])).stdout.trim();
    check(sameBrowserFile(before, after, quarantine, renamedQuarantine), "browser_inode_or_quarantine_changed");
    return { dmg: named, pid };
  } finally {
    stopBegin(); stopProgress(); browser.close(); page.close();
  }
}

export function firstLaunchObservation({ document: doc = document, getComputedStyle: styleOf = getComputedStyle } = {}) {
  const visible = (element) => {
    if (!element) return false;
    const rect = element.getBoundingClientRect();
    const style = styleOf(element);
    return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
  };
  const editor = Array.from(doc.querySelectorAll('textarea[aria-label="Prompt"], [data-component="prompt-input"][contenteditable="true"]'))
    .find((element) => visible(element) && element.getAttribute("aria-disabled") !== "true" && !element.disabled && !element.readOnly);
  return !!editor && doc.body.innerText.includes("Program AI Desktop") &&
    !/Something went wrong|An error occurred while loading the application|Stale read from <Show>/.test(doc.body.innerText);
}

export async function verifyInstall() {
  const pins = await loadPins();
  const record = { flow: "install", arch: process.env.VERIFY_ARCH, version: pins.version, status: "unverified", checks: [], phase: "preflight" };
  const observePhase = (phase) => { record.phase = phase; };
  const observeLaunch = (value) => { record.launch = launchObservation(value); };
  let root, mount, mounted = false, appPid, chromePid, renderer;
  let chromeLaunchAttempted = false, appLaunchAttempted = false;
  let guarded = false;
  try {
    const context = await requireCiContext(pins);
    guarded = true;
    record.arch = context.arch;
    record.checks.push("native_host");
    await ensureFreshHost(pins);
    check((await run("/usr/sbin/spctl", ["--status"])).stdout.includes("assessments enabled"), "gatekeeper_not_enabled");
    const runnerTemp = await realpath(process.env.RUNNER_TEMP ?? "");
    const temporaryInfo = await lstat(runnerTemp);
    check(runnerTemp.startsWith("/Users/runner/") && temporaryInfo.isDirectory() && temporaryInfo.uid === process.getuid(),
      "runner_temporary_unverified");
    root = await mkdtemp(path.join(runnerTemp, "program-ai-install-"));
    const artifact = pins.artifacts[context.arch];
    observePhase("zip_download");
    const zip = await downloadPinned(artifact.zip, path.join(root, artifact.zip.name));
    record.checks.push("zip_bytes");
    const zipApp = await extractZip(zip, path.join(root, "zip-preflight"));
    observePhase("zip_verify");
    const expected = await verifyApp(zipApp, { pins, arch: context.arch });
    record.checks.push("zip_app_signature", "zip_app_ticket");
    // Current ZIP-contained app trust is established before any browser launch.
    await mkdir(path.join(homedir(), "Downloads"), { recursive: true });
    const downloads = await realpath(await mkdtemp(path.join(homedir(), "Downloads/program-ai-verification-")));
    const downloaded = await browserDownload(root, downloads, artifact.dmg, () => { chromeLaunchAttempted = true; },
      observePhase, observeLaunch, (gui) => { record.gui = gui; });
    chromePid = downloaded.pid;
    record.checks.push("headed_browser_download", "genuine_quarantine", "dmg_bytes");
    observePhase("dmg_verify");
    await verifyDmg(downloaded.dmg, { pins });
    record.checks.push("dmg_signature", "dmg_ticket");
    mount = path.join(root, "mounted-dmg");
    await mkdir(mount);
    observePhase("dmg_mount");
    await run("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount, downloaded.dmg]);
    mounted = true;
    const sourceApp = path.join(mount, "Program AI Desktop.app");
    observePhase("mounted_verify");
    const mountedIdentity = await verifyApp(sourceApp, { pins, arch: context.arch });
    check(mountedIdentity.cdhash === expected.cdhash && mountedIdentity.asarSha256 === expected.asarSha256,
      "zip_dmg_app_mismatch", "failed");
    await run("/usr/bin/xattr", ["-p", "com.apple.quarantine", sourceApp], { code: "mounted_quarantine_unverified" });
    record.checks.push("mounted_app");
    await assertAbsent(INSTALLED_APP);
    observePhase("finder_install");
    await run("/usr/bin/osascript", ["-e", `tell application "Finder" to duplicate POSIX file ${JSON.stringify(sourceApp)} to POSIX file "/Applications"`],
      { env: applicationEnvironment(), code: "finder_install_unverified" });
    observePhase("installed_verify");
    const installed = await verifyApp(INSTALLED_APP, { pins, arch: context.arch });
    check(installed.cdhash === expected.cdhash && installed.asarSha256 === expected.asarSha256,
      "finder_installed_app_mismatch", "failed");
    await run("/usr/bin/xattr", ["-p", "com.apple.quarantine", INSTALLED_APP], { code: "installed_quarantine_unverified" });
    record.checks.push("finder_install");
    await run("/usr/bin/hdiutil", ["detach", mount]); mounted = false;
    const port = await unusedPort();
    const observation = { context: "application", pidCount: 0, listener: "not_checked", openStatus: "pending", openExitCode: null,
      openTimedOut: false, dialogApproved: false };
    observePhase("application_launch"); observeLaunch(observation);
    appLaunchAttempted = true;
    const launched = run("/usr/bin/open", ["-n", "-a", INSTALLED_APP, "--args", `--remote-debugging-port=${port}`, "--remote-debugging-address=127.0.0.1"],
      { env: applicationEnvironment(), code: "native_first_launch_unverified", allowFailure: true })
      .then((result) => opening(result, observation, observeLaunch), () => opening({ exitCode: null, timedOut: false }, observation, observeLaunch));
    appPid = await ownedDiagnosticPort(installed.executable, port, "Program AI Desktop", observation, observeLaunch);
    check(await launched, "native_first_launch_unverified");
    record.checks.push("native_launch");
    observePhase("renderer_connect");
    renderer = await connectCdp(port, appPid, { executable: installed.executable });
    await waitFor(() => renderer.evaluate("!!window.api?.awaitInitialization"), { timeoutMs: 90000, code: "preload_readiness_unverified" });
    observePhase("sidecar_ready");
    const sidecar = await renderer.evaluate(`(async () => {
      const server = await window.api.awaitInitialization();
      const url = new URL(server.url);
      if (url.protocol !== 'http:' || !['127.0.0.1','localhost','[::1]'].includes(url.hostname) || url.username || url.password) return false;
      const headers = server.password ? {authorization:'Basic '+btoa((server.username || 'program-ai')+':'+server.password)} : {};
      const response = await fetch(new URL('/global/health', url), {headers, signal:AbortSignal.timeout(10000)});
      return response.ok && (await response.json()).healthy === true;
    })()`, 90000);
    check(sidecar === true, "native_sidecar_health_failed", "failed");
    record.checks.push("sidecar_ready");
    observePhase("renderer_ready");
    await waitFor(() => renderer.evaluate(`(${firstLaunchObservation.toString()})()`), { timeoutMs: 90000, code: "native_renderer_readiness_unverified" });
    record.checks.push("renderer_ready");
    check(await renderer.evaluate("window.api.programAICloudAuth.getState().then(value => value.status === 'signed_out')") === true,
      "fresh_account_state_unverified");
    record.checks.push("signed_out");
    observePhase("local_typing");
    const typed = await renderer.evaluate(`(() => {
      const element = Array.from(document.querySelectorAll('textarea[aria-label="Prompt"], [data-component="prompt-input"][contenteditable="true"]')).find(node=>node.getBoundingClientRect().height>0);
      if (!element) return false;
      const text = 'Local verification only. Never submitted.';
      if ('value' in element) element.value=text; else element.textContent=text;
      element.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:text}));
      const retained = ('value' in element ? element.value : element.textContent) === text;
      if ('value' in element) element.value=''; else element.textContent='';
      element.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'deleteContentBackward'}));
      return retained;
    })()`);
    check(typed === true, "native_local_typing_failed", "failed");
    record.checks.push("local_typing");
    check((await run("/usr/sbin/spctl", ["--status"])).stdout.includes("assessments enabled"), "gatekeeper_state_changed");
    record.status = "passed";
    observePhase("completed");
  } catch (error) {
    record.status = error instanceof VerificationFailure ? error.kind : "unverified";
    record.code = error instanceof VerificationFailure ? error.code : "unexpected_verification_failure";
  } finally {
    renderer?.close();
    if (guarded) {
      try {
        if (!appPid && appLaunchAttempted) {
          const pids = await findOwnedPids(`${INSTALLED_APP}/Contents/MacOS/Program AI Desktop`);
          if (pids.length === 1) appPid = pids[0];
        }
        if (appPid) await terminateOwned(`${INSTALLED_APP}/Contents/MacOS/Program AI Desktop`, appPid);
        if (!chromePid && chromeLaunchAttempted) {
          const pids = await findOwnedPids(CHROME_EXECUTABLE);
          if (pids.length === 1) chromePid = pids[0];
        }
        if (chromePid) await terminateOwned(CHROME_EXECUTABLE, chromePid);
        if (mounted) await run("/usr/bin/hdiutil", ["detach", mount]);
        record.checks.push("cleanup");
      } catch {
        record.status = "unverified"; record.code = "owned_cleanup_unverified"; observePhase("cleanup");
      }
    }
    // Never emit raw exceptions, native command output, browser URLs, tokens,
    // screenshots, profiles, downloaded bytes, or private app contents.
    if (["arm64", "x64"].includes(record.arch)) await emitReceipt(record);
    else console.log(JSON.stringify({ schemaVersion: 1, flow: "install", status: "unverified", code: "fresh_native_public_ci_required" }));
  }
  return record;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  await verifyInstall().then((result) => { if (result.status !== "passed") process.exitCode = 1; }, () => {
    console.log(JSON.stringify({ schemaVersion: 1, flow: "install", status: "unverified", code: "verification_preflight_unverified" }));
    process.exitCode = 1;
  });
}
