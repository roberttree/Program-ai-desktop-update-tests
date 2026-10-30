import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { chromeLaunchArguments, firstLaunchObservation, launchFailureCode, normalDownloadPreferences, normalOpenDialog, sameBrowserFile, validDownloadEvent } from "./verify-install.mjs";

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
  assert.ok(browser.indexOf('"--assess", "--type", "execute", CHROME') < browser.indexOf("startHeadfulChrome("));
  assert.doesNotMatch(browser, /run\("\/usr\/bin\/open"/);
  assert.doesNotMatch(source, /(?:Browser|Page)\.setDownloadBehavior|allowAndName/);
  assert.match(browser, /page\.onEvent\("Page\.downloadWillBegin"/);
  assert.match(browser, /page\.onEvent\("Page\.downloadProgress"/);
  assert.match(browser, /event\.state === "completed"/);
  assert.ok(browser.indexOf("normalDownloadPreferences(downloads)") < browser.indexOf("startHeadfulChrome("));
  assert.ok(browser.indexOf("completed && begun") < browser.indexOf("await sha256File(original)"));
  assert.match(browser, /genuineQuarantineRead\(attribute, started\)/);
  assert.doesNotMatch(source, /xattr[^\n]*(?:-d|-c|-w)|spctl[^\n]*(?:--master-disable|--disable)|tccutil|fuses\.write|\.updater\.install|chat\/completions/);
  assert.doesNotMatch(flow, /press\(.?Enter|key.?\s*:\s*.Enter/);
});
