import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { appleTranslocationOrigin, browserSignatureDiagnostic, chromeLaunchArguments, createProgramLaunchResolver, firstLaunchObservation, inspectNormalOpenAgent, launchFailureCode, normalDownloadPreferences,
  normalOpenButtonFacts, normalOpenDialog, normalOpenErrorFlags, normalOpenQueryDiagnostic, programLaunchCandidates, programLaunchProcessCounts, sameBrowserFile,
  translocatedAppPath, validDownloadEvent, verifyQuarantineInheritance } from "./verify-install.mjs";

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

function normalDialogFixture({ text = '“Program AI Desktop” is an app downloaded from the Internet. Are you sure you want to open it?', valueAvailable = true, valueError, role = "AXStaticText", buttons = ["Cancel", "Open"], extraSubrole } = {}) {
  let clicked = 0; const clickedNames = [];
  const leaf = (role, name) => ({ role: () => role, name: () => name, uiElements: () => [], click: () => { clicked++; clickedNames.push(name); } });
  const content = { ...leaf(role, text), attributes: { byName: () => ({ exists: () => valueAvailable,
    value: () => { if (valueError) throw valueError; return text; } }) } };
  const window = { role: () => "AXWindow", uiElements: () => [content, ...buttons.map((name) => ({ ...leaf("AXButton", name),
    attributes: { byName: (attribute) => ({ exists: () => attribute === "AXSubrole" && extraSubrole !== undefined, value: () => extraSubrole }) } }))] };
  return { agent: { exists: () => true, windows: () => [window] }, clicked: () => clicked, clickedNames: () => clickedNames };
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

test("extra Open-dialog buttons are identified only by bounded categories and never speculatively permitted", () => {
  for (const [name, category] of [["Show Web Page", "show_web_page"], ["Help", "help"], ["?", "question_mark"], ["private unknown text", "unknown"]]) {
    const fixture = normalDialogFixture({ buttons: ["Cancel", "Open", name] });
    const observed = inspectNormalOpenAgent(fixture.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags);
    const receipt = normalOpenQueryDiagnostic({ exitCode: 0, stdout: JSON.stringify(observed) });
    assert.equal(receipt.cancelButtonCount, 1); assert.equal(receipt.extraButtonCount, 1);
    assert.equal(receipt.extraButtonCategory, category); assert.equal(receipt.approved, false); assert.equal(fixture.clicked(), 0);
    assert.doesNotMatch(JSON.stringify(receipt), /private unknown text|Show Web Page/);
  }
  assert.equal(normalOpenButtonFacts(["Open", "Cancel"]).extraButtonCategory, "none");
  assert.equal(normalOpenButtonFacts(["Open", "Cancel", "Help", "?"]).extraButtonCategory, "multiple");
  assert.equal(normalOpenButtonFacts(Array(20).fill("private")).extraButtonCount, 16);
});

test("unknown extra button labels are RAM-only and public diagnostics contain only bounded kinds, subrole and SHA256", () => {
  for (const [name, nameKind] of [[undefined, "missing"], ["", "empty"], ["private unrecognized label", "nonempty"]]) {
    const fixture = normalDialogFixture({ buttons: ["Cancel", "Open", name], extraSubrole: "AXHelpButton" });
    const privateValue = inspectNormalOpenAgent(fixture.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags);
    const receipt = normalOpenQueryDiagnostic({ exitCode: 0, stdout: JSON.stringify(privateValue) });
    assert.equal(receipt.extraButtonCategory, "ax_help_button");
    assert.deepEqual(receipt.extraButtons, [{ nameKind, nameLength: name?.length ?? 0, nameTooLong: false, subrole: "AXHelpButton",
      labelSha256: typeof name === "string" ? createHash("sha256").update(name).digest("hex") : null }]);
    assert.equal(receipt.approved, false); assert.equal(fixture.clicked(), 0);
    assert.doesNotMatch(JSON.stringify(receipt), /private unrecognized label|privateExtraButtons|"label"/);
  }
  const oversized = normalDialogFixture({ buttons: ["Cancel", "Open", "x".repeat(65)], extraSubrole: "private unknown subrole" });
  const receipt = normalOpenQueryDiagnostic({ exitCode: 0, stdout: JSON.stringify(inspectNormalOpenAgent(oversized.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags)) });
  assert.deepEqual(receipt.extraButtons, [{ nameKind: "nonempty", nameLength: 64, nameTooLong: true, subrole: "other", labelSha256: null }]);
  assert.equal(receipt.approved, false); assert.doesNotMatch(JSON.stringify(receipt), /private unknown subrole/);
  const malformed = normalOpenQueryDiagnostic({ exitCode: 0, stdout: JSON.stringify({ privateExtraButtons: Array(20).fill({ nameKind: "private", nameLength: 1000, subrole: "private", label: "/private/value" }) }) });
  assert.equal(malformed.extraButtons.length, 16);
  assert.doesNotMatch(JSON.stringify(malformed), /\/private\/value|"private"/);
});

test("observed optional unnamed OS control permits only literal Open and retains the ordinary consent classifier", () => {
  for (const name of [undefined, null, ""]) {
    const fixture = normalDialogFixture({ buttons: ["Cancel", "Open", name] });
    const observed = inspectNormalOpenAgent(fixture.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags);
    const receipt = normalOpenQueryDiagnostic({ exitCode: 0, stdout: JSON.stringify(observed) });
    assert.equal(observed.approved, true); assert.equal(receipt.approved, true);
    assert.deepEqual(fixture.clickedNames(), ["Open"]); // Never the unnamed control.
    assert.equal(receipt.extraButtons[0].nameLength, 0); assert.equal(receipt.extraButtons[0].subrole, "missing");
    assert.equal(receipt.extraButtons[0].nameKind, name === "" ? "empty" : "missing");
  }
  const two = normalDialogFixture();
  assert.equal(inspectNormalOpenAgent(two.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags).approved, true);
  assert.deepEqual(two.clickedNames(), ["Open"]);
});

test("unnamed-control tolerance rejects every named, duplicate, boolean, control-character or ambiguous extra", () => {
  for (const buttons of [["Cancel", "Open", "Open Anyway"], ["Cancel", "Open", "Trash"], ["Cancel", "Open", "private unknown label"],
    ["Cancel", "Open", "Help"], ["Cancel", "Open", "?"], ["Cancel", "Open", "Show Web Page"], ["Cancel", "Open", false],
    ["Cancel", "Open", true], ["Cancel", "Open", 0], ["Cancel", "Open", {}], ["Cancel", "Open", "\u0000"],
    ["Cancel", "Open", " "], ["Cancel", "Open", "Open\u0000"], ["Cancel", "Open", "Open"], ["Cancel", "Cancel", "Open"],
    ["Cancel", "Open", undefined, undefined]]) {
    const fixture = normalDialogFixture({ buttons });
    const observed = inspectNormalOpenAgent(fixture.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags);
    assert.equal(observed.approved, false); assert.equal(fixture.clicked(), 0);
    assert.equal(normalOpenQueryDiagnostic({ exitCode: 0, stdout: JSON.stringify(observed) }).approved, false);
  }
  for (const options of [{ extraSubrole: "AXHelpButton" }, { text: null, valueAvailable: false },
    { text: "Program AI Desktop is downloaded from the Internet. Are you sure you want to open it? It is damaged." }]) {
    const fixture = normalDialogFixture({ buttons: ["Cancel", "Open", undefined], ...options });
    const observed = inspectNormalOpenAgent(fixture.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags);
    assert.equal(observed.approved, false); assert.equal(fixture.clicked(), 0);
  }
});

test("public approval needs exact observed extra-control metadata and cannot accept invented labels or malformed proof", () => {
  const fixture = normalDialogFixture({ buttons: ["Cancel", "Open", undefined] });
  const observed = inspectNormalOpenAgent(fixture.agent, "Program AI Desktop", normalOpenDialog, normalOpenErrorFlags);
  for (const fields of [{ nameLength: 1 }, { nameLength: null }, { nameTooLong: true }, { nameTooLong: "false" },
    { subrole: "AXHelpButton" }, { subrole: "other" }, { nameKind: "nonempty" }, { label: "private injected control" }]) {
    const value = { ...observed, privateExtraButtons: [{ ...observed.privateExtraButtons[0], ...fields }] };
    const receipt = normalOpenQueryDiagnostic({ exitCode: 0, stdout: JSON.stringify(value) });
    assert.equal(receipt.approved, false); assert.doesNotMatch(JSON.stringify(receipt), /private injected control/);
  }
  const dialog = { text: ['Program AI Desktop is downloaded from the Internet. Are you sure you want to open it?'], buttons: ["Cancel", "Open", undefined] };
  assert.equal(normalOpenDialog(dialog, "Program AI Desktop"), false);
  assert.equal(normalOpenDialog({ ...dialog, extraButtons: null }, "Program AI Desktop"), false);
});

const installedApp = "/Applications/Program AI Desktop.app";
const translocatedApp = "/private/var/folders/ab/owned_test/T/AppTranslocation/12345678-1234-1234-1234-123456789abc/d/Program AI Desktop.app";
const mainExecutable = (app) => `${app}/Contents/MacOS/Program AI Desktop`;
const appleOriginResult = (app = installedApp) => ({ exitCode: 0,
  stdout: `Original Path: (note if this is what you passed in then that path is not translocated)\n\t${app}\n` });

test("AppTranslocation candidates require the exact canonical Apple UUID layout and main executable", () => {
  const executable = mainExecutable(translocatedApp);
  assert.equal(translocatedAppPath(executable), translocatedApp);
  for (const invalid of [executable.replace("/private/var", "/var"), executable.replace("AppTranslocation", "other"),
    executable.replace("123456789abc", "not-a-uuid"), executable + " Helper", executable.replace("/d/", "/d/../d/"),
    executable.replace("/T/", "/C/"), executable.replace("Program AI Desktop.app", "Other.app")]) assert.equal(translocatedAppPath(invalid), undefined);
  assert.deepEqual(programLaunchCandidates(` 42 ${executable}\n 43 ${mainExecutable(installedApp)}\n 1 ${executable}\n 44 /Users/private/other\n`), [
    { pid: 42, executable, app: translocatedApp, mode: "translocated" },
    { pid: 43, executable: mainExecutable(installedApp), app: installedApp, mode: "installed" },
  ]);
});

test("Apple translocation origin must be confirmed by successful status and exact original installed app", () => {
  const status = { exitCode: 0, stdout: "\tTRANSLOCATED\n" };
  assert.equal(appleTranslocationOrigin(status, appleOriginResult(), installedApp), true);
  for (const invalid of [{ ...status, exitCode: 1 }, { ...status, stdout: "NOT TRANSLOCATED" }, { ...status, stdout: "TRANSLOCATED\nextra" }])
    assert.equal(appleTranslocationOrigin(invalid, appleOriginResult(), installedApp), false);
  for (const original of [appleOriginResult("/Applications/Other.app"), { ...appleOriginResult(), exitCode: 1 },
    { exitCode: 0, stdout: installedApp }, { exitCode: 0, stdout: appleOriginResult().stdout + "extra\n" }])
    assert.equal(appleTranslocationOrigin(status, original, installedApp), false);
});

function translocationFixture(options = {}) {
  const expected = { version: "1.0.10", cdhash: "candidate-cdhash", asarSha256: "candidate-asar" };
  const installed = { ...expected, executable: mainExecutable(installedApp) };
  const calls = [];
  const dependencies = {
    realpath: async (value) => value === options.nonCanonical ? `${value}/other` : value,
    run: async (command, args) => {
      calls.push([command, ...args]);
      if (command === "/bin/ps") return { exitCode: 0, stdout: options.processes ?? `42 ${mainExecutable(translocatedApp)}\n` };
      if (args[0] === "translocate-status-check") return { exitCode: 0, stdout: options.status ?? "TRANSLOCATED" };
      if (args[0] === "translocate-original-path") return appleOriginResult(options.origin ?? installedApp);
      throw new Error("unexpected fixture command");
    },
    verifyApp: async (app, context) => {
      calls.push(["verifyApp", app, context.arch]);
      if (options.trustFailure) throw options.trustFailure;
      return { ...expected, executable: mainExecutable(app), ...options.actual };
    },
    findOwnedPids: async (executable) => { calls.push(["findOwnedPids", executable]); return options.pids ?? [42]; },
  };
  return { resolve: createProgramLaunchResolver({ pins: { version: "1.0.10" }, arch: "arm64", expected, installed }, dependencies), calls };
}

test("translocated owner requires Apple origin plus full candidate trust before exact PID ownership", async () => {
  const fixture = translocationFixture();
  assert.deepEqual(await fixture.resolve(), [{ pid: 42, executable: mainExecutable(translocatedApp), app: translocatedApp, mode: "translocated" }]);
  const verifyIndex = fixture.calls.findIndex(([name]) => name === "verifyApp");
  assert.ok(verifyIndex > fixture.calls.findIndex(([, action]) => action === "translocate-original-path"));
  assert.ok(verifyIndex < fixture.calls.findIndex(([name]) => name === "findOwnedPids"));
  assert.equal(fixture.calls[verifyIndex][2], "arm64");
  await fixture.resolve(); // Cache trust only for the same exact PID/path; recheck process ownership each poll.
  assert.equal(fixture.calls.filter(([name]) => name === "verifyApp").length, 1);
  assert.equal(fixture.calls.filter(([name]) => name === "findOwnedPids").length, 2);
  const direct = translocationFixture({ processes: `42 ${mainExecutable(installedApp)}\n` });
  assert.equal((await direct.resolve())[0].mode, "installed");
  assert.equal(direct.calls.some(([name]) => name === "/usr/bin/security" || name === "verifyApp"), false);
});

test("translocated ownership rejects incorrect origin, canonical path, trust, candidate bytes and process PID", async () => {
  for (const options of [{ status: "NOT TRANSLOCATED" }, { origin: "/Applications/Other.app" }]) {
    const fixture = translocationFixture(options);
    await assert.rejects(fixture.resolve(), { code: "translocated_origin_unverified" });
    assert.equal(fixture.calls.some(([name]) => name === "verifyApp"), false);
  }
  await assert.rejects(translocationFixture({ nonCanonical: translocatedApp }).resolve(), { code: "translocated_path_not_canonical" });
  for (const actual of [{ version: "1.0.9" }, { cdhash: "wrong" }, { asarSha256: "wrong" }, { executable: mainExecutable(installedApp) }])
    await assert.rejects(translocationFixture({ actual }).resolve(), { code: "translocated_candidate_mismatch", kind: "failed" });
  await assert.rejects(translocationFixture({ trustFailure: Object.assign(new Error("fixed"), { code: "app_signature_invalid" }) }).resolve(), { code: "app_signature_invalid" });
  for (const pids of [[], [43], [42, 43]]) await assert.rejects(translocationFixture({ pids }).resolve(), { code: "translocated_process_owner_unverified" });
  const ambiguous = translocationFixture({ processes: `42 ${mainExecutable(translocatedApp)}\n43 ${mainExecutable(installedApp)}\n` });
  assert.equal((await ambiguous.resolve()).length, 2);
  assert.equal(ambiguous.calls.some(([name]) => name === "verifyApp" || name === "findOwnedPids"), false);
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
