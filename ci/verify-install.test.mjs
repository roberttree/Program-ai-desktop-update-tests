import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { firstLaunchObservation, normalOpenDialog, sameBrowserFile, validDownloadEvent } from "./verify-install.mjs";

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
  assert.doesNotMatch(source, /xattr[^\n]*(?:-d|-c|-w)|spctl[^\n]*(?:--master-disable|--disable)|tccutil|fuses\.write|\.updater\.install|chat\/completions/);
  assert.doesNotMatch(flow, /press\(.?Enter|key.?\s*:\s*.Enter/);
});
