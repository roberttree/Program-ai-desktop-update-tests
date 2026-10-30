import { lstat, mkdir, mkdtemp, realpath, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  VerificationFailure, applicationEnvironment, approvedRedirect, assertAbsent, check, connectCdp, downloadPinned,
  emitReceipt, ensureFreshHost, extractZip, findOwnedPids, launchObservation, loadPins,
  quarantineReadObservation, quarantineRecord, requireCiContext, run, sha256File, terminateOwned, unusedPort, verifyApp, verifyDmg, verifyListener, waitFor,
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

export function browserSignatureDiagnostic(result) {
  const exitCode = Number.isInteger(result.exitCode) && result.exitCode >= 0 && result.exitCode <= 255 ? result.exitCode : null;
  const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.slice(0, 131072);
  const failed = exitCode !== 0;
  const fields = { code_modified: failed && /code or signature (?:have|has) been modified|file modified:/i.test(text),
    resource_missing: failed && /sealed resource is missing|file missing:|resource.*not found/i.test(text),
    unsealed: failed && /unsealed (?:contents|resource)|unsealed directory/i.test(text),
    not_signed: failed && /not signed at all|code object is not signed|no signature found/i.test(text),
    trust_service: failed && /trust service|trust evaluation|CSSMERR_TP|errSecInternalComponent|unable to build chain|certificate chain/i.test(text) };
  // These are diagnostic-message predicates, not a replacement for verification.
  return { exitCode, ...fields, unknown: failed && !Object.values(fields).some(Boolean) };
}

export function sameBrowserFile(before, after, quarantineBefore, quarantineAfter) {
  return before.isFile() && after.isFile() && !before.isSymbolicLink() && !after.isSymbolicLink() &&
    before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.size > 0 &&
    quarantineBefore === quarantineAfter;
}

export function genuineQuarantineRead(result, startedMs, nowMs = Date.now()) {
  const observed = quarantineReadObservation(result, startedMs, nowMs);
  console.log(JSON.stringify({ schemaVersion: 1, check: "browser_quarantine", ...observed }));
  check(observed.readStatus !== "missing", "browser_quarantine_missing");
  check(observed.readStatus === "present", "browser_quarantine_read_error");
  try { quarantineRecord(result.stdout, startedMs, nowMs); }
  catch { throw new VerificationFailure("unverified", "browser_quarantine_parser_rejected"); }
  return result.stdout.trim();
}

export function verifyQuarantineInheritance(source, installed, startedMs, nowMs = Date.now()) {
  try { quarantineRecord(source, startedMs, nowMs); quarantineRecord(installed, startedMs, nowMs); }
  catch { throw new VerificationFailure("unverified", "installed_quarantine_unverified"); }
  const original = source.trim().split(";"), copied = installed.trim().split(";");
  const originalTime = Number.parseInt(original[1], 16) * 1000;
  const copiedTime = Number.parseInt(copied[1], 16) * 1000;
  // Finder may create a new quarantine event identifier. Require the same
  // browser agent and download/copy time context, not byte-identical UUIDs.
  check(copied[2] === original[2] && copiedTime >= originalTime - 60000 && copiedTime <= nowMs + 60000,
    "installed_quarantine_context_mismatch");
  return true;
}

export function normalOpenErrorFlags(message, code) {
  const text = typeof message === "string" ? message.slice(0, 16384) : "";
  return { automationDenied: code === -1743 || /not authorized to send apple events|not permitted to send apple events|\(-1743\)/i.test(text),
    accessibilityDenied: code === -25211 || /not allowed assistive access|accessibility access (?:is )?denied|AXErrorAPIDisabled|\(-25211\)/i.test(text),
    attributeUnavailable: code === -1728 || /unsupported attribute|attribute.*not supported/i.test(text) };
}

export function normalOpenButtonFacts(buttons) {
  const values = Array.isArray(buttons) ? buttons : [];
  const extra = values.filter((name) => name !== "Open" && name !== "Cancel");
  const known = new Map([["Show Web Page", "show_web_page"], ["Help", "help"], ["?", "question_mark"]]);
  return { cancelButtonCount: Math.min(16, values.filter((name) => name === "Cancel").length),
    extraButtonCount: Math.min(16, extra.length),
    extraButtonCategory: extra.length === 0 ? "none" : extra.length > 1 ? "multiple" : known.get(extra[0]) ?? "unknown" };
}

export function inspectNormalOpenAgent(agent, application, classify, errorFlags, buttonFacts = normalOpenButtonFacts) {
  const observed = { status: "query_failed", querySucceeded: false, agentPresent: false, windowCount: 0, staticTextCount: 0,
    valueAvailableCount: 0, nameFallbackCount: 0, unreadableTextCount: 0, buttonCount: 0, openButtonCount: 0,
    automationDenied: false, accessibilityDenied: false, classifierMatched: false, approved: false,
    expectedApplication: false, downloadedWarning: false, openConfirmation: false, blockedWarning: false };
  const bounded = (value) => typeof value === "string" && value.length > 0 && value.length <= 2048;
  const failure = (error) => {
    const flags = errorFlags(error?.message, error?.number);
    observed.automationDenied ||= flags.automationDenied;
    observed.accessibilityDenied ||= flags.accessibilityDenied;
    return flags;
  };
  try {
    if (!agent.exists()) { observed.querySucceeded = true; observed.status = "agent_missing"; return observed; }
    observed.agentPresent = true;
    const windows = agent.windows(); observed.windowCount = Math.min(windows.length, 16);
    if (windows.length !== 1) { observed.querySucceeded = true; observed.status = "window_count"; return observed; }
    const text = [], buttons = [], open = [], privateExtraButtons = []; let visited = 0;
    const visit = (node, depth) => {
      if (++visited > 256 || depth > 10) throw new Error("bounded");
      const role = node.role();
      if (role === "AXStaticText") {
        observed.staticTextCount = Math.min(16, observed.staticTextCount + 1);
        let value;
        try { const attribute = node.attributes.byName("AXValue"); if (attribute.exists()) value = attribute.value(); }
        catch (error) { const flags = failure(error); if (!flags.attributeUnavailable || flags.automationDenied || flags.accessibilityDenied) throw error; }
        if (typeof value === "string" && value.length > 2048) throw new Error("bounded");
        if (bounded(value) && value.trim()) observed.valueAvailableCount = Math.min(16, observed.valueAvailableCount + 1);
        else {
          // Name is read only for AXStaticText whose AXValue is unavailable.
          // The original full normalOpenDialog classifier is not relaxed.
          value = node.name();
          if (bounded(value) && value.trim()) observed.nameFallbackCount = Math.min(16, observed.nameFallbackCount + 1);
          else { observed.unreadableTextCount = Math.min(16, observed.unreadableTextCount + 1); value = undefined; }
        }
        text.push(value);
      }
      if (role === "AXButton") {
        const name = node.name(); buttons.push(name); if (name === "Open") open.push(node);
        if (name !== "Open" && name !== "Cancel") {
          let subrole;
          try { const attribute = node.attributes?.byName("AXSubrole"); if (attribute?.exists()) subrole = attribute.value(); }
          catch (error) { const flags = failure(error); if (!flags.attributeUnavailable || flags.automationDenied || flags.accessibilityDenied) throw error; }
          if (privateExtraButtons.length < 16) privateExtraButtons.push({
            nameKind: typeof name !== "string" ? "missing" : name.length === 0 ? "empty" : "nonempty",
            nameLength: typeof name === "string" ? Math.min(64, name.length) : 0,
            nameTooLong: typeof name === "string" && name.length > 64,
            subrole: subrole === "AXHelpButton" ? "AXHelpButton" : subrole === undefined || subrole === null || subrole === "" ? "missing" : "other",
            // Private osascript -> Node RAM only. The public projection hashes
            // this bounded name and never emits the label or other AX text.
            ...(typeof name === "string" && name.length <= 64 ? { label: name } : {}),
          });
        }
      }
      node.uiElements().forEach((child) => visit(child, depth + 1));
    };
    visit(windows[0], 0);
    observed.buttonCount = Math.min(buttons.length, 16); observed.openButtonCount = Math.min(open.length, 16);
    Object.assign(observed, buttonFacts(buttons));
    observed.privateExtraButtons = privateExtraButtons;
    if (observed.extraButtonCategory === "unknown" && privateExtraButtons.length === 1 && privateExtraButtons[0].subrole === "AXHelpButton")
      observed.extraButtonCategory = "ax_help_button";
    const words = text.filter((item) => bounded(item)).join(" ");
    observed.expectedApplication = text.some((item) => bounded(item) && item.includes(application));
    observed.downloadedWarning = /downloaded from the internet/i.test(words);
    observed.openConfirmation = /are you sure.*open/i.test(words);
    observed.blockedWarning = /damaged|malware|cannot be opened|can.t be opened|unidentified|open anyway|trash|bin/i.test(words);
    observed.querySucceeded = true;
    observed.classifierMatched = classify({ text, buttons }, application) && open.length === 1;
    if (!observed.classifierMatched || observed.automationDenied || observed.accessibilityDenied) { observed.status = "classifier_nonmatch"; return observed; }
    open[0].click(); observed.approved = true; observed.status = "approved";
  } catch (error) {
    failure(error); observed.querySucceeded = false;
    observed.status = observed.automationDenied || observed.accessibilityDenied ? "access_denied" : error?.message === "bounded" ? "bounded" : "query_failed";
  }
  return observed;
}

export function normalOpenQueryDiagnostic(result) {
  let value = {};
  try {
    if (result.exitCode === 0 && result.stdout?.length <= 16384) {
      const parsed = JSON.parse(result.stdout);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) value = parsed;
    }
  } catch {}
  const flags = normalOpenErrorFlags(result.stderr);
  const output = { queryExitCode: Number.isInteger(result.exitCode) && result.exitCode >= 0 && result.exitCode <= 255 ? result.exitCode : null,
    queryTimedOut: result.timedOut === true, querySucceeded: result.exitCode === 0 && value.querySucceeded === true,
    status: ["agent_missing", "window_count", "classifier_nonmatch", "approved", "access_denied", "bounded", "query_failed"].includes(value.status) ? value.status : "query_failed" };
  for (const name of ["agentPresent", "automationDenied", "accessibilityDenied", "classifierMatched", "expectedApplication", "downloadedWarning", "openConfirmation", "blockedWarning"])
    output[name] = value[name] === true;
  output.automationDenied ||= flags.automationDenied; output.accessibilityDenied ||= flags.accessibilityDenied;
  if (output.automationDenied || output.accessibilityDenied) { output.status = "access_denied"; output.querySucceeded = false; }
  for (const name of ["windowCount", "staticTextCount", "valueAvailableCount", "nameFallbackCount", "unreadableTextCount", "buttonCount", "openButtonCount", "cancelButtonCount", "extraButtonCount"])
    output[name] = Number.isInteger(value[name]) && value[name] >= 0 ? Math.min(16, value[name]) : 0;
  output.extraButtonCategory = ["none", "multiple", "show_web_page", "help", "question_mark", "ax_help_button", "unknown"].includes(value.extraButtonCategory) ? value.extraButtonCategory : "unknown";
  output.extraButtons = (Array.isArray(value.privateExtraButtons) ? value.privateExtraButtons : []).slice(0, 16).map((button) => ({
    nameKind: ["empty", "nonempty", "missing"].includes(button?.nameKind) ? button.nameKind : "missing",
    nameLength: Number.isInteger(button?.nameLength) && button.nameLength >= 0 ? Math.min(64, button.nameLength) : 0,
    nameTooLong: button?.nameTooLong === true,
    subrole: ["AXHelpButton", "other", "missing"].includes(button?.subrole) ? button.subrole : "missing",
    labelSha256: typeof button?.label === "string" && button.label.length <= 64 ? createHash("sha256").update(button.label).digest("hex") : null,
  }));
  output.approved = result.exitCode === 0 && output.querySucceeded && output.status === "approved" && value.approved === true &&
    output.classifierMatched && output.windowCount === 1 && output.buttonCount === 2 && output.openButtonCount === 1 &&
    output.cancelButtonCount === 1 && output.extraButtonCount === 0 && output.extraButtonCategory === "none";
  return output;
}

export function programLaunchProcessCounts(text) {
  const paths = typeof text === "string" ? text.split("\n").map((line) => line.trim()) : [];
  return { installedProcessCount: Math.min(16, paths.filter((item) => item === `${INSTALLED_APP}/Contents/MacOS/Program AI Desktop`).length),
    translocatedProcessCount: Math.min(16, paths.filter((item) => /^\/(?:private\/)?var\/folders\/[^\r\n]*\/AppTranslocation\/[A-Za-z0-9-]+\/d\/Program AI Desktop\.app\/Contents\/MacOS\/Program AI Desktop$/.test(item)).length) };
}

export function translocatedAppPath(executable) {
  if (typeof executable !== "string") return undefined;
  const match = /^(\/private\/var\/folders\/[A-Za-z0-9_-]{2}\/[A-Za-z0-9_-]{1,128}\/T\/AppTranslocation\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\/d\/Program AI Desktop\.app)\/Contents\/MacOS\/Program AI Desktop$/i.exec(executable);
  return match?.[1];
}

export function programLaunchCandidates(text) {
  if (typeof text !== "string" || text.length > 4 * 1024 * 1024) return [];
  return text.split("\n").flatMap((line) => {
    const match = /^\s*([1-9][0-9]*)\s+(.+?)\s*$/.exec(line);
    if (!match || !Number.isSafeInteger(Number(match[1])) || Number(match[1]) <= 1) return [];
    const executable = match[2], app = translocatedAppPath(executable);
    return executable === `${INSTALLED_APP}/Contents/MacOS/Program AI Desktop` || app ?
      [{ pid: Number(match[1]), executable, app: app ?? INSTALLED_APP, mode: app ? "translocated" : "installed" }] : [];
  });
}

export function appleTranslocationOrigin(status, original, installedApp) {
  // These read-only SecurityTool commands call Apple's translocation service.
  // A path spelling alone is not evidence that Apple created the mapping.
  // https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/translocate.c
  const lines = typeof original.stdout === "string" && original.stdout.length <= 8192 ? original.stdout.trim().split("\n").map((line) => line.trim()) : [];
  return status.exitCode === 0 && status.stdout?.trim() === "TRANSLOCATED" && original.exitCode === 0 &&
    lines.length === 2 && lines[0] === "Original Path: (note if this is what you passed in then that path is not translocated)" &&
    lines[1] === installedApp;
}

export function createProgramLaunchResolver({ pins, arch, expected, installed }, dependencies = {}) {
  const io = { run, realpath, findOwnedPids, verifyApp, ...dependencies };
  let verified;
  return async () => {
    check(await io.realpath(INSTALLED_APP) === INSTALLED_APP && installed.executable === `${INSTALLED_APP}/Contents/MacOS/Program AI Desktop` &&
      installed.cdhash === expected.cdhash && installed.asarSha256 === expected.asarSha256, "installed_launch_identity_unverified");
    const processes = await io.run("/bin/ps", ["-axo", "pid=,comm="], { maxBytes: 4 * 1024 * 1024 });
    const candidates = programLaunchCandidates(processes.stdout);
    // Multiple candidates are observations only. No candidate is attached to or
    // terminated unless the sole exact executable is fully verified below.
    if (candidates.length !== 1) return candidates;
    const candidate = candidates[0];
    check(await io.realpath(candidate.app) === candidate.app && await io.realpath(candidate.executable) === candidate.executable,
      "translocated_path_not_canonical");
    if (candidate.mode === "translocated" && (verified?.pid !== candidate.pid || verified?.executable !== candidate.executable)) {
      const status = await io.run("/usr/bin/security", ["translocate-status-check", candidate.app], { allowFailure: true, maxBytes: 8192 });
      const original = await io.run("/usr/bin/security", ["translocate-original-path", candidate.app], { allowFailure: true, maxBytes: 8192 });
      check(appleTranslocationOrigin(status, original, INSTALLED_APP), "translocated_origin_unverified");
      const actual = await io.verifyApp(candidate.app, { pins, arch });
      check(actual.executable === candidate.executable && actual.version === expected.version && actual.cdhash === expected.cdhash &&
        actual.asarSha256 === expected.asarSha256, "translocated_candidate_mismatch", "failed");
    }
    const owners = await io.findOwnedPids(candidate.executable);
    check(owners.length === 1 && owners[0] === candidate.pid, "translocated_process_owner_unverified");
    verified = candidate;
    return [candidate];
  };
}

const normalOpenHistory = new Map();
async function approveNormalOpen(application) {
  // Only the unchanged full exact-name Open/Cancel classifier can click. No
  // grants, OS security changes or unclassified dialogs are actionable.
  const script = `JSON.stringify((${inspectNormalOpenAgent.toString()})(Application("System Events").applicationProcesses.byName("CoreServicesUIAgent"),${JSON.stringify(application)},(${normalOpenDialog.toString()}),(${normalOpenErrorFlags.toString()}),(${normalOpenButtonFacts.toString()})))`;
  const result = await run("/usr/bin/osascript", ["-l", "JavaScript", "-e", script], { timeoutMs: 10000, maxBytes: 16384, allowFailure: true });
  const diagnostic = normalOpenQueryDiagnostic(result);
  const processes = application === "Program AI Desktop" ? await run("/bin/ps", ["-axo", "comm="], { allowFailure: true, timeoutMs: 5000, maxBytes: 4 * 1024 * 1024 }) : undefined;
  const record = { schemaVersion: 1, check: "normal_open_dialog", subject: application === "Program AI Desktop" ? "application" : "browser",
    ...diagnostic, processCountsChecked: processes?.exitCode === 0,
    ...programLaunchProcessCounts(processes?.exitCode === 0 ? processes.stdout : "") };
  const serialized = JSON.stringify(record), previous = normalOpenHistory.get(record.subject) ?? { count: 0 };
  if (previous.count < 16 && previous.last !== serialized) { console.log(serialized); normalOpenHistory.set(record.subject, { last: serialized, count: previous.count + 1 }); }
  return diagnostic.approved;
}

export function launchFailureCode(value) {
  const observation = launchObservation(value);
  const suffix = observation.processStatus === "error" ? "spawn_failed" : observation.processStatus === "exited" ? "process_exited" :
    observation.openStatus === "failed" ? "open_failed" : observation.pidCount === 0 ? "process_missing" :
    observation.pidCount > 1 ? "process_ambiguous" : "listener_unverified";
  return `${observation.context}_${suffix}`;
}

async function ownedDiagnosticPort(executable, port, application, observation, observe, resolveOwners) {
  let observedOwner;
  const ownerFailures = new Set();
  try {
    return await waitFor(async () => {
      let owners;
      try { owners = resolveOwners ? await resolveOwners() : (await findOwnedPids(executable)).map((pid) => ({ pid, executable })); }
      catch (error) {
        if (error instanceof VerificationFailure && error.kind === "failed") throw error;
        if (application === "Program AI Desktop" && ["installed_launch_identity_unverified", "translocated_path_not_canonical",
          "translocated_origin_unverified", "translocated_process_owner_unverified"].includes(error?.code) && !ownerFailures.has(error.code)) {
          ownerFailures.add(error.code);
          console.log(JSON.stringify({ schemaVersion: 1, check: "application_launch_owner", status: "unverified", code: error.code }));
        }
        observation.dialogApproved = await approveNormalOpen(application) || observation.dialogApproved;
        observe(observation); throw error;
      }
      observation.pidCount = Math.min(owners.length, 2);
      if (owners.length !== 1) {
        observation.listener = "not_checked";
        observation.dialogApproved = await approveNormalOpen(application) || observation.dialogApproved;
        observe(observation); return false;
      }
      if (application === "Program AI Desktop" && ["installed", "translocated"].includes(owners[0].mode) &&
        observedOwner !== owners[0].mode) {
        console.log(JSON.stringify({ schemaVersion: 1, check: "application_launch_owner", mode: owners[0].mode, status: "verified" }));
        observedOwner = owners[0].mode;
      }
      observation.listener = "unverified"; observe(observation);
      try { await verifyListener(port, owners[0].pid, owners[0].executable); }
      catch (error) {
        if (error instanceof VerificationFailure && error.kind === "failed") throw error;
        observation.dialogApproved = await approveNormalOpen(application) || observation.dialogApproved;
        observe(observation); return false;
      }
      observation.listener = "ready"; observe(observation);
      return owners[0];
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

export function chromeLaunchArguments(profile, port) {
  check(path.isAbsolute(profile) && Number.isInteger(port) && port > 0 && port < 65536, "browser_arguments_invalid");
  return [`--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, "--remote-debugging-address=127.0.0.1",
    "--no-first-run", "--no-default-browser-check", "about:blank"];
}

export function normalDownloadPreferences(downloads) {
  check(typeof downloads === "string" && /^\/Users\/runner\/Downloads\/program-ai-verification-[A-Za-z0-9]{6}$/.test(downloads),
    "browser_download_directory_invalid");
  // Use Chrome's ordinary target selection/quarantine pipeline. DevTools
  // download-behavior overrides replace its normal download manager delegate.
  return { download: { default_directory: downloads, prompt_for_download: false } };
}

function startHeadfulChrome(profile, port, observation, observe) {
  // Only the preflight-verified official browser is directly spawned. No
  // headless/security switches or application-launch shortcuts are introduced.
  const child = spawn(CHROME_EXECUTABLE, chromeLaunchArguments(profile, port), {
    env: applicationEnvironment(), stdio: ["ignore", "ignore", "ignore"],
  });
  let exited;
  const stopped = new Promise((resolve) => { exited = resolve; });
  const started = new Promise((resolve) => {
    child.once("spawn", () => { observation.processStatus = "spawned"; observe(observation); resolve(true); });
    child.once("error", () => { observation.processStatus = "error"; observe(observation); resolve(false); exited(); });
  });
  child.once("exit", (code) => {
    observation.processStatus = "exited";
    observation.processExitCode = Number.isInteger(code) && code >= 0 && code <= 255 ? code : null;
    observe(observation); exited();
  });
  return { child, started, stopped };
}

async function browserDownload(root, downloads, artifact, onLaunch, observePhase, observeLaunch, observeGui) {
  observePhase("browser_preflight");
  const info = JSON.parse((await run("/usr/bin/plutil", ["-convert", "json", "-o", "-", `${CHROME}/Contents/Info.plist`])).stdout);
  check(info.CFBundleIdentifier === "com.google.Chrome" && info.LSFileQuarantineEnabled === true,
    "browser_quarantine_capability_unverified");
  const browserSignature = await run("/usr/bin/codesign", ["--verify", "--deep", "--strict", CHROME], { allowFailure: true, maxBytes: 65536 });
  console.log(JSON.stringify({ schemaVersion: 1, check: "browser_signature", ...browserSignatureDiagnostic(browserSignature) }));
  check(browserSignature.exitCode === 0, "browser_signature_unverified");
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
  const profile = path.join(root, "browser-profile");
  await assertAbsent(profile);
  await assertAbsent(path.join(downloads, artifact.name));
  await mkdir(path.join(profile, "Default"), { recursive: true, mode: 0o700 });
  await writeFile(path.join(profile, "Default/Preferences"), JSON.stringify(normalDownloadPreferences(downloads)), { flag: "wx", mode: 0o600 });
  const observation = { context: "browser", launcherMode: "direct_vendor_browser", pidCount: 0, listener: "not_checked",
    openStatus: "not_used", openExitCode: null, openTimedOut: false, dialogApproved: false, processStatus: "pending", processExitCode: null };
  observePhase("browser_launch"); observeLaunch(observation);
  const launcher = startHeadfulChrome(profile, port, observation, observeLaunch);
  onLaunch(launcher);
  check(await launcher.started, "headed_browser_spawn_unverified");
  const { pid } = await ownedDiagnosticPort(CHROME_EXECUTABLE, port, "Google Chrome", observation, observeLaunch);
  check(pid === launcher.child.pid, "browser_process_owner_unverified");
  observePhase("browser_connect");
  const page = await connectCdp(port, pid, { executable: CHROME_EXECUTABLE });
  let begun;
  let completed = false;
  // Page's normal download events observe actual DownloadItems when Page is
  // enabled; they do not require replacing Chrome's download delegate.
  const stopBegin = page.onEvent("Page.downloadWillBegin", (event) => { if (validDownloadEvent(event, artifact)) begun = event; });
  const stopProgress = page.onEvent("Page.downloadProgress", (event) => {
    if (begun && event.guid === begun.guid && event.state === "completed") completed = true;
  });
  try {
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
    const original = path.join(downloads, artifact.name);
    check((await realpath(original)) === original, "browser_download_path_invalid");
    const before = await lstat(original);
    check(before.isFile() && !before.isSymbolicLink() && before.size === artifact.bytes &&
      await sha256File(original) === artifact.sha256, "browser_artifact_mismatch", "failed");
    const attribute = await run("/usr/bin/xattr", ["-p", "com.apple.quarantine", original], { allowFailure: true, maxBytes: 4096 });
    const quarantine = genuineQuarantineRead(attribute, started);
    const after = await lstat(original);
    const unchangedQuarantine = (await run("/usr/bin/xattr", ["-p", "com.apple.quarantine", original])).stdout.trim();
    check(sameBrowserFile(before, after, quarantine, unchangedQuarantine), "browser_inode_or_quarantine_changed");
    return { dmg: original, pid, quarantine, started, identity: after };
  } finally {
    stopBegin(); stopProgress(); page.close();
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
  const observeLaunch = (value) => {
    const observation = launchObservation(value);
    if (observation.context === "browser") record.browserLaunch = observation;
    if (record.launch?.context !== "application" || observation.context === "application") record.launch = observation;
  };
  let root, mount, mounted = false, appPid, appExecutable, appOwners, chromePid, renderer, browserStarted, browserStopped, applicationStarted;
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
    const downloaded = await browserDownload(root, downloads, artifact.dmg, (launcher) => {
      chromeLaunchAttempted = true; browserStarted = launcher.started; browserStopped = launcher.stopped; chromePid = launcher.child.pid;
    },
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
    // A read-only image's contents need not carry a physical bundle xattr.
    // Apple DTS describes the DMG -> Finder copy -> Gatekeeper inheritance
    // chain; the installed copy below remains a mandatory quarantine gate.
    const mountedAttribute = await run("/usr/bin/xattr", ["-p", "com.apple.quarantine", sourceApp], { allowFailure: true, maxBytes: 4096 });
    console.log(JSON.stringify({ schemaVersion: 1, check: "mounted_quarantine", ...quarantineReadObservation(mountedAttribute, downloaded.started) }));
    record.checks.push("mounted_app");
    await assertAbsent(INSTALLED_APP);
    observePhase("finder_install");
    const originalAttribute = await run("/usr/bin/xattr", ["-p", "com.apple.quarantine", downloaded.dmg], { allowFailure: true, maxBytes: 4096 });
    console.log(JSON.stringify({ schemaVersion: 1, check: "source_dmg_quarantine", ...quarantineReadObservation(originalAttribute, downloaded.started) }));
    check(originalAttribute.exitCode === 0 && sameBrowserFile(downloaded.identity, await lstat(downloaded.dmg),
      downloaded.quarantine, originalAttribute.stdout.trim()) && await sha256File(downloaded.dmg) === artifact.dmg.sha256,
      "source_dmg_or_quarantine_changed");
    await run("/usr/bin/osascript", ["-e", `tell application "Finder" to duplicate POSIX file ${JSON.stringify(sourceApp)} to POSIX file "/Applications"`],
      { env: applicationEnvironment(), code: "finder_install_unverified" });
    observePhase("installed_verify");
    const installed = await verifyApp(INSTALLED_APP, { pins, arch: context.arch });
    check(installed.cdhash === expected.cdhash && installed.asarSha256 === expected.asarSha256,
      "finder_installed_app_mismatch", "failed");
    const installedAttribute = await run("/usr/bin/xattr", ["-p", "com.apple.quarantine", INSTALLED_APP], { allowFailure: true, maxBytes: 4096 });
    console.log(JSON.stringify({ schemaVersion: 1, check: "installed_quarantine", ...quarantineReadObservation(installedAttribute, downloaded.started) }));
    check(installedAttribute.exitCode === 0, "installed_quarantine_unverified");
    verifyQuarantineInheritance(downloaded.quarantine, installedAttribute.stdout, downloaded.started);
    record.checks.push("finder_install");
    await run("/usr/bin/hdiutil", ["detach", mount]); mounted = false;
    appOwners = createProgramLaunchResolver({ pins, arch: context.arch, expected, installed });
    const port = await unusedPort();
    const observation = { context: "application", launcherMode: "launch_services", pidCount: 0, listener: "not_checked", openStatus: "pending", openExitCode: null,
      openTimedOut: false, dialogApproved: false };
    observePhase("application_launch"); observeLaunch(observation);
    appLaunchAttempted = true;
    const launched = run("/usr/bin/open", ["-n", "-a", INSTALLED_APP, "--args", `--remote-debugging-port=${port}`, "--remote-debugging-address=127.0.0.1"],
      { env: applicationEnvironment(), code: "native_first_launch_unverified", allowFailure: true })
      .then((result) => opening(result, observation, observeLaunch), () => opening({ exitCode: null, timedOut: false }, observation, observeLaunch));
    applicationStarted = launched;
    const appOwner = await ownedDiagnosticPort(installed.executable, port, "Program AI Desktop", observation, observeLaunch, appOwners);
    appPid = appOwner.pid; appExecutable = appOwner.executable;
    check(await launched, "native_first_launch_unverified");
    record.checks.push("native_launch");
    observePhase("renderer_connect");
    renderer = await connectCdp(port, appPid, { executable: appExecutable });
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
        // Settle owned launch attempts before inspecting/terminating their
        // exact processes, so no delayed launcher can start after cleanup.
        await browserStarted;
        await applicationStarted;
        if (!appPid && appLaunchAttempted) {
          const owners = await appOwners();
          check(owners.length <= 1, "cleanup_ownership_unverified");
          if (owners.length === 1) { appPid = owners[0].pid; appExecutable = owners[0].executable; }
        }
        if (appPid) await terminateOwned(appExecutable, appPid);
        if (!chromePid && chromeLaunchAttempted) {
          const pids = await findOwnedPids(CHROME_EXECUTABLE);
          if (pids.length === 1) chromePid = pids[0];
        }
        if (chromePid) await terminateOwned(CHROME_EXECUTABLE, chromePid);
        await browserStopped;
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
