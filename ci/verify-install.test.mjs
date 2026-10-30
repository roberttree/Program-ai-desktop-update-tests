import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { browserSignatureDiagnostic, chromeLaunchArguments, firstLaunchObservation, inspectNormalOpenAgent, launchFailureCode, normalDownloadPreferences,
  normalOpenDialog, normalOpenErrorFlags, normalOpenQueryDiagnostic, programLaunchProcessCounts, sameBrowserFile, validDownloadEvent, verifyQuarantineInheritance } from "./verify-install.mjs";

test("vendor Chrome signature diagnostics expose fixed categories/exit only and never relax strict verification", () => {
  for (const [stderr, category] of [["private/path: code or signature have been modified", "code_modified"],
    ["private/path: a sealed resource is missing or invalid", "resource_missing"], ["private/path: unsealed contents present", "unsealed"],
    ["private/path: code object is not signed at all", "not_signed"], ["private/path: CSSMERR_TP_NOT_TRUSTED", "trust_service"]]) {
    const result = browserSignatureDiagnostic({ exitCode: 1, stderr });
    assert.equal(result[category], true); assert.equal(result.exitCode, 1); assert.equal(result.unknown, false);
    assert.doesNotMatch(JSON.stringify(result), /private|CSSMERR|modified present/);
  }
  const unknown = browserSignatureDiagnostic({ exitCode: null, stderr: "private unknown error" });
  assert.equal(unknown.unknown, true); assert.equal(unknown.exitCode, null);
  const valid = browserSignatureDiagnostic({ exitCode: 0 });
  assert.equal(Object.entries(valid).some(([name, value]) => name !== "exitCode" && value), false);
});

function normalDialogFixture({ text = '“Program AI Desktop” is an app downloaded from the Internet. Are you sure you want to open it?', valueAvailable = true, valueError, role = "AXStaticText" } = {}) {
  let clicked = 0;
  const leaf = (role, name) => ({ role: () => role, name: () => name, uiElements: () => [], click: () => { clicked++; } });
  const content = { ...leaf(role, text), attributes: { byName: () => ({ exists: () => valueAvailable,
    value: () => { if (valueError) throw valueError; return text; } }) } };
  const window = { role: () => "AXWindow", uiElements: () => [content, leaf("AXButton", "Cancel"), leaf("AXButton", "Open")] };
  return { agent: { exists: () => true, windows: () => [window] }, clicked: () => clicked };
}

test("normal Open diagnostics distinguish missing agent/windows, actual access denial and generic query errors", () => {
  const inspect = (agent) => inspectNormalOpenAgent(agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags);
  assert.equal(inspect({ exists: () => false }).status, "agent_missing");
  for (const windows of [[], [{}, {}]]) {
    const result = inspect({ exists: () => true, windows: () => windows });
    assert.equal(result.status, "window_count"); assert.equal(result.windowCount, windows.length); assert.equal(result.approved, false);
  }
  for (const [message, number, field] of [["not authorized to send Apple events", -1743, "automationDenied"],
    ["not allowed assistive access", -1719, "accessibilityDenied"]]) {
    const error = Object.assign(new Error(message), { number });
    const result = inspect({ exists: () => { throw error; } });
    assert.equal(result.status, "access_denied"); assert.equal(result[field], true); assert.equal(result.approved, false);
  }
  const generic = inspect({ exists: () => { throw Object.assign(new Error("Invalid index"), { number: -1719 }); } });
  assert.equal(generic.status, "query_failed"); assert.equal(generic.accessibilityDenied, false);
});

test("AXStaticText value/name availability is observable without weakening the full Open classifier", () => {
  const inspect = (fixture) => inspectNormalOpenAgent(fixture.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags);
  const normal = normalDialogFixture(); const valid = inspect(normal);
  assert.equal(valid.approved, true); assert.equal(normal.clicked(), 1); assert.equal(valid.valueAvailableCount, 1);
  const fallback = normalDialogFixture({ valueAvailable: false }); const readName = inspect(fallback);
  assert.equal(readName.approved, true); assert.equal(readName.nameFallbackCount, 1); assert.equal(fallback.clicked(), 1);
  const nonText = normalDialogFixture({ role: "AXGroup", valueAvailable: false });
  assert.equal(inspect(nonText).approved, false); assert.equal(nonText.clicked(), 0);
  const damaged = normalDialogFixture({ text: "Program AI Desktop is downloaded from the Internet. Are you sure you want to open it? It is damaged." });
  const blocked = inspect(damaged); assert.equal(blocked.blockedWarning, true); assert.equal(blocked.classifierMatched, false); assert.equal(damaged.clicked(), 0);
  const denied = normalDialogFixture({ valueError: Object.assign(new Error("not allowed assistive access"), { number: -1719 }) });
  assert.equal(inspect(denied).status, "access_denied"); assert.equal(denied.clicked(), 0);
  const oversized = normalDialogFixture({ text: "x".repeat(2049) });
  assert.equal(inspect(oversized).status, "bounded"); assert.equal(oversized.clicked(), 0);
});

test("normal Open query receipts are fixed and never grant approval on denied or malformed queries", () => {
  const fixture = normalDialogFixture();
  const observed = inspectNormalOpenAgent(fixture.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags);
  const result = normalOpenQueryDiagnostic({ exitCode: 0, stdout: JSON.stringify({ ...observed, rawText: "private text", path: "/Users/private" }) });
  assert.equal(result.approved, true); assert.equal(result.queryExitCode, 0);
  assert.doesNotMatch(JSON.stringify(result), /private|Program AI|Internet/);
  const denied = normalOpenQueryDiagnostic({ exitCode: 1, stderr: "private path: not authorized to send Apple events (-1743)" });
  assert.equal(denied.automationDenied, true); assert.equal(denied.approved, false); assert.equal(denied.querySucceeded, false);
  for (const stdout of ["null", "true", "[]", "not JSON"])
    assert.equal(normalOpenQueryDiagnostic({ exitCode: 0, stdout }).approved, false);
  assert.equal(normalOpenQueryDiagnostic({ exitCode: null, timedOut: true }).queryTimedOut, true);
});

test("AppTranslocation process facts count only expected main binaries and never expose paths or PIDs", () => {
  const installed = "/Applications/Program AI Desktop.app/Contents/MacOS/Program AI Desktop";
  const moved = "/private/var/folders/private-value/T/AppTranslocation/12345678-1234/d/Program AI Desktop.app/Contents/MacOS/Program AI Desktop";
  const counts = programLaunchProcessCounts([installed, moved, moved + " Helper (Renderer)", "/Users/private/other"].join("\n"));
  assert.deepEqual(counts, { installedProcessCount: 1, translocatedProcessCount: 1 });
  assert.doesNotMatch(JSON.stringify(counts), /private|12345678|Applications/);
  assert.equal(programLaunchProcessCounts(Array(20).fill(moved).join("\n")).translocatedProcessCount, 16);
});

test("Finder-installed copy requires genuine matching browser/time context but may have a new quarantine UUID", () => {
  const now = 1800000000000;
  const timestamp = Math.floor(now / 1000).toString(16);
  const source = `0083;${timestamp};Google Chrome;12345678-1234-1234-1234-123456789abc`;
  const copied = source.replace("12345678-1234-1234-1234-123456789abc", "87654321-1234-1234-1234-cba987654321");
  assert.equal(verifyQuarantineInheritance(source, copied, now, now), true);
  assert.equal(verifyQuarantineInheritance(source, copied.replace("0083", "0081"), now, now), true);
  for (const invalid of ["", copied.replace("0083", "0000"), copied.replace("Google Chrome", "Finder"),
    copied.replace(timestamp, "00000001"), copied.replace("87654321", "invalid")])
    assert.throws(() => verifyQuarantineInheritance(source, invalid, now, now), { code: "installed_quarantine_unverified" });
  assert.throws(() => verifyQuarantineInheritance(source, copied.replace("Google Chrome", "Chrome"), now, now), { code: "installed_quarantine_context_mismatch" });
});

test("normal download preferences target only the fresh CI-owned Downloads directory without security preferences", () => {
  const directory = "/Users/runner/Downloads/program-ai-verification-a1B2c3";
  assert.deepEqual(normalDownloadPreferences(directory), { download: { default_directory: directory, prompt_for_download: false } });
  for (const invalid of ["/Users/owner/Downloads/program-ai-verification-a1B2c3", directory + "/..", "/private/tmp/download", "/Users/runner/Downloads"])
    assert.throws(() => normalDownloadPreferences(invalid), { code: "browser_download_directory_invalid" });
});

test("verified vendor browser arguments remain headful, loopback-only and contain no security bypass flags", () => {
  assert.deepEqual(chromeLaunchArguments("/Users/runner/work/_temp/owned/browser-profile", 1234), [
    "--user-data-dir=/Users/runner/work/_temp/owned/browser-profile", "--remote-debugging-port=1234", "--remote-debugging-address=127.0.0.1",
    "--no-first-run", "--no-default-browser-check", "about:blank",
  ]);
  for (const port of [0, 65536, 1.5]) assert.throws(() => chromeLaunchArguments("/Users/runner/owned", port), { code: "browser_arguments_invalid" });
  assert.throws(() => chromeLaunchArguments("relative", 1234), { code: "browser_arguments_invalid" });
});

test("launch capability failures distinguish exact-owner PID, listener and open outcomes without calling them app failures", () => {
  const value = { context: "browser", pidCount: 0, listener: "not_checked", openStatus: "pending", openExitCode: null,
    openTimedOut: false, dialogApproved: false };
  assert.equal(launchFailureCode(value), "browser_process_missing");
  assert.equal(launchFailureCode({ ...value, pidCount: 2 }), "browser_process_ambiguous");
  assert.equal(launchFailureCode({ ...value, pidCount: 1, listener: "unverified", openStatus: "succeeded", openExitCode: 0 }), "browser_listener_unverified");
  assert.equal(launchFailureCode({ ...value, openStatus: "failed", openExitCode: 1 }), "browser_open_failed");
  assert.equal(launchFailureCode({ ...value, context: "application", openStatus: "failed", openTimedOut: true }), "application_open_failed");
});

test("only the ordinary exact-name downloaded-app Open/Cancel dialog is eligible", () => {
  const dialog = { text: ['“Program AI Desktop” is an app downloaded from the Internet. Are you sure you want to open it?'], buttons: ["Cancel", "Open"] };
  assert.equal(normalOpenDialog(dialog, "Program AI Desktop"), true);
  for (const invalid of [
    { ...dialog, buttons: ["Open Anyway", "Cancel"] },
    { ...dialog, text: ["Program AI Desktop is damaged and cannot be opened"] },
    { ...dialog, text: ['“Other app” is an app downloaded from the Internet. Are you sure you want to open it?'] },
    { ...dialog, buttons: ["Open", "Cancel", "Allow"] },
  ]) assert.equal(normalOpenDialog(invalid, "Program AI Desktop"), false);
  assert.equal(normalOpenDialog(dialog, "Unrelated App"), false);
});

test("download events need expected filename, canonical GUID and approved HTTPS host; bytes are separately pinned", () => {
  const artifact = { name: "Program-AI-Desktop-mac-arm64.dmg" };
  const event = { guid: "12345678-1234-1234-1234-123456789abc", suggestedFilename: artifact.name,
    url: "https://release-assets.githubusercontent.com/signed-asset?signature=opaque" };
  assert.equal(validDownloadEvent(event, artifact), true);
  assert.equal(validDownloadEvent({ ...event, guid: "../../escape" }, artifact), false);
  assert.equal(validDownloadEvent({ ...event, url: "https://other.invalid/file" }, artifact), false);
  assert.equal(validDownloadEvent({ ...event, suggestedFilename: "wrong.dmg" }, artifact), false);
});

test("renaming a browser download must preserve inode, size and the original quarantine value", () => {
  const file = { dev: 1, ino: 42, size: 1024, isFile: () => true, isSymbolicLink: () => false };
  assert.equal(sameBrowserFile(file, { ...file }, "original", "original"), true);
  for (const changed of [{ ...file, ino: 43 }, { ...file, size: 1 }, { ...file, isSymbolicLink: () => true }])
    assert.equal(sameBrowserFile(file, changed, "original", "original"), false);
  assert.equal(sameBrowserFile(file, file, "original", "new"), false);
});

test("meaningful first launch requires a visible usable composer and product identity, not just a window", () => {
  const editor = { getBoundingClientRect: () => ({ width: 400, height: 100 }), getAttribute: () => null, disabled: false, readOnly: false };
  const document = { querySelectorAll: () => [editor], body: { innerText: "Program AI Desktop" } };
  const getComputedStyle = () => ({ display: "block", visibility: "visible" });
  assert.equal(firstLaunchObservation({ document, getComputedStyle }), true);
  assert.equal(firstLaunchObservation({ document: { ...document, querySelectorAll: () => [] }, getComputedStyle }), false);
  assert.equal(firstLaunchObservation({ document, getComputedStyle: () => ({ display: "none", visibility: "visible" }) }), false);
  assert.equal(firstLaunchObservation({ document: { ...document, body: { innerText: "Program AI Desktop Something went wrong" } }, getComputedStyle }), false);
  editor.disabled = true;
  assert.equal(firstLaunchObservation({ document, getComputedStyle }), false);
});

test("the actual driver guards first, proves ZIP app trust before Chrome, and never submits a prompt", async () => {
  const source = await readFile(new URL("./verify-install.mjs", import.meta.url), "utf8");
  const flow = source.slice(source.indexOf("export async function verifyInstall()"));
  assert.ok(flow.indexOf("await requireCiContext(pins)") < flow.indexOf("await downloadPinned("));
  assert.ok(flow.indexOf("await verifyApp(zipApp") < flow.indexOf("await browserDownload("));
  assert.match(flow, /await verifyDmg\(downloaded\.dmg/);
  assert.match(flow, /same|zip_dmg_app_mismatch/);
  assert.match(flow, /finder_install/);
  assert.match(flow, /\/global\/health/);
  assert.match(source, /consoleUserIsRunner/);
  assert.match(source, /guiBootstrapAvailable/);
  assert.match(source, /allowFailure: true/);
  assert.match(source, /observePhase\("browser_launch"\)/);
  assert.match(source, /observePhase\("application_launch"\)/);
  assert.match(source, /spawn\(CHROME_EXECUTABLE/);
  assert.doesNotMatch(flow, /spawn\(|execFile\(/); // Application first launch remains LaunchServices.
  assert.match(flow, /run\("\/usr\/bin\/open", \["-n", "-a", INSTALLED_APP/);
  assert.match(flow, /await browserStarted/);
  assert.match(flow, /await applicationStarted/);
  assert.match(flow, /await browserStopped/);
  const browser = source.slice(source.indexOf("async function browserDownload("), source.indexOf("export function firstLaunchObservation("));
  assert.ok(browser.indexOf('"--verify", "--deep", "--strict", CHROME') < browser.indexOf("startHeadfulChrome("));
  assert.match(browser, /check\(browserSignature\.exitCode === 0, "browser_signature_unverified"\)/);
  assert.match(browser, /check: "browser_signature"/);
  assert.ok(browser.indexOf('"--assess", "--type", "execute", CHROME') < browser.indexOf("startHeadfulChrome("));
  assert.doesNotMatch(browser, /run\("\/usr\/bin\/open"/);
  assert.doesNotMatch(source, /(?:Browser|Page)\.setDownloadBehavior|allowAndName/);
  assert.match(browser, /page\.onEvent\("Page\.downloadWillBegin"/);
  assert.match(browser, /page\.onEvent\("Page\.downloadProgress"/);
  assert.match(browser, /event\.state === "completed"/);
  assert.ok(browser.indexOf("normalDownloadPreferences(downloads)") < browser.indexOf("startHeadfulChrome("));
  assert.ok(browser.indexOf("completed && begun") < browser.indexOf("await sha256File(original)"));
  assert.match(browser, /genuineQuarantineRead\(attribute, started\)/);
  assert.doesNotMatch(source, /mounted_quarantine_unverified/);
  assert.match(flow, /check: "mounted_quarantine"/);
  assert.match(flow, /sameBrowserFile\(downloaded\.identity/);
  assert.match(flow, /source_dmg_or_quarantine_changed/);
  assert.ok(flow.indexOf("verifyQuarantineInheritance(downloaded.quarantine") < flow.indexOf('run("/usr/bin/open", ["-n", "-a", INSTALLED_APP'));
  assert.match(flow, /check\(installedAttribute\.exitCode === 0, "installed_quarantine_unverified"\)/);
  assert.doesNotMatch(source, /xattr[^\n]*(?:-d|-c|-w)|spctl[^\n]*(?:--master-disable|--disable)|tccutil|fuses\.write|\.updater\.install|chat\/completions/);
  assert.doesNotMatch(flow, /press\(.?Enter|key.?\s*:\s*.Enter/);
  assert.match(source, /return diagnostic\.approved/);
  assert.match(source, /check: "normal_open_dialog"/);
  assert.match(source, /previous\.count < 16/);
  const ownership = source.slice(source.indexOf("async function ownedDiagnosticPort("), source.indexOf("function opening("));
  assert.doesNotMatch(ownership, /translocatedProcessCount|programLaunchProcessCounts/);
});
