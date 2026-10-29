import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  PUBLIC_REPOSITORY, VerificationFailure, approvedRedirect, loopbackWebSocket, parseUpdaterConfiguration,
  quarantineRecord, receipt, signatureIdentity, validateArtifact, validateCiFacts, validatePins, validateZipArchive,
} from "./runtime.mjs";

const hash = "a".repeat(64);
function facts(arch = "arm64") {
  return {
    platform: "darwin", arch, hardwareArch: arch, translated: false, home: "/Users/runner",
    accountHome: "/Users/runner", username: "runner", uid: 501,
    env: { CI: "true", GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", RUNNER_OS: "macOS",
      RUNNER_ARCH: arch === "arm64" ? "ARM64" : "X64", GITHUB_REPOSITORY: PUBLIC_REPOSITORY,
      GITHUB_REF: "refs/heads/main", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_ACTOR_ID: "88110976",
      GITHUB_TRIGGERING_ACTOR: "roberttree", GITHUB_RUN_ID: "1234", GITHUB_SHA: "a".repeat(40) },
  };
}
function artifact(arch, extension, version = "1.0.9") {
  const name = `Program-AI-Desktop-mac-${arch}.${extension}`;
  return { name, bytes: 1024, sha256: hash, url: `https://github.com/${PUBLIC_REPOSITORY}/releases/download/v${version}/${name}` };
}
function pins() {
  return { schemaVersion: 1, repository: PUBLIC_REPOSITORY, version: "1.0.9", baseVersion: "1.0.8",
    teamId: "LH2479Y2F4", bundleId: "com.programai.desktop",
    source: { repository: "roberttree/Program-ai-desktop", commit: "a".repeat(40), tag: "program-ai-desktop-v1.0.9", tagObject: "b".repeat(40) },
    artifacts: Object.fromEntries(["arm64", "x64"].map((arch) => [arch, {
      dmg: artifact(arch, "dmg"), zip: artifact(arch, "zip"), zipBlockmap: artifact(arch, "zip.blockmap"), baseZip: artifact(arch, "zip", "1.0.8"),
    }])) };
}
const failure = (callback, code) => assert.throws(callback, (error) => error instanceof VerificationFailure && error.code === code);

test("pure host policy admits native public ARM and Intel facts, not an emulation claim", () => {
  assert.equal(validateCiFacts(facts(), "arm64"), "arm64");
  assert.equal(validateCiFacts(facts("x64"), "x64"), "x64");
  const translated = facts("x64"); translated.hardwareArch = "arm64"; translated.translated = true;
  failure(() => validateCiFacts(translated, "x64"), "fresh_native_public_ci_required");
});

test("owner workstation, spoofed HOME, private repository, PR and non-owner contexts fail closed", () => {
  for (const patch of [
    { home: "/Users/roberttree" }, { accountHome: "/Users/roberttree" }, { username: "roberttree" },
    { platform: "linux" }, { uid: 0 }, { hardwareArch: "x64" },
  ]) failure(() => validateCiFacts({ ...facts(), ...patch }, "arm64"), "fresh_native_public_ci_required");
  for (const patch of [
    { GITHUB_REPOSITORY: "roberttree/Program-ai-desktop" }, { GITHUB_EVENT_NAME: "pull_request" },
    { GITHUB_REF: "refs/heads/verify-mac-release" }, { GITHUB_ACTOR_ID: "1" }, { GITHUB_TRIGGERING_ACTOR: "someone" },
    { RUNNER_ENVIRONMENT: "self-hosted" }, { GITHUB_ACTIONS: "false" }, { RUNNER_ARCH: "X64" },
  ]) { const value = facts(); Object.assign(value.env, patch); failure(() => validateCiFacts(value, "arm64"), "fresh_native_public_ci_required"); }
});

test("candidate metadata identifies both exact archives, DMGs, blockmaps and previous signed version", () => {
  assert.equal(validatePins(pins()).version, "1.0.9");
  for (const key of ["version", "baseVersion", "teamId", "bundleId", "repository"]) {
    const value = pins(); value[key] = "invalid";
    failure(() => validatePins(value), "candidate_identity_invalid");
  }
  const missing = pins(); delete missing.artifacts.x64.zipBlockmap;
  failure(() => validatePins(missing), "artifact_pin_invalid");
  const old = pins(); old.artifacts.arm64.zip.url = old.artifacts.arm64.baseZip.url;
  failure(() => validatePins(old), "artifact_url_invalid");
});

test("artifact URL and byte pins reject private-source downloads, secret URLs and unbounded inputs", () => {
  const value = artifact("arm64", "dmg");
  for (const url of [value.url.replace("https:", "http:"), value.url + "?token=private", value.url + "#fragment",
    value.url.replace("github.com", "github.com.evil.invalid"), value.url.replace(PUBLIC_REPOSITORY, "roberttree/Program-ai-desktop"),
    value.url.replace("github.com", "user:password@github.com")]) {
    failure(() => validateArtifact({ ...value, url }, "arm64", "dmg", "1.0.9"), "artifact_url_invalid");
  }
  for (const patch of [{ bytes: 0 }, { bytes: 513 * 1024 * 1024 }, { sha256: "invalid" }, { name: "../file.dmg" }])
    failure(() => validateArtifact({ ...value, ...patch }, "arm64", "dmg", "1.0.9"), "artifact_pin_invalid");
});

test("redirects admit only GitHub's bounded HTTPS artifact hosts and diagnostic sockets only loopback", () => {
  assert.equal(approvedRedirect("https://release-assets.githubusercontent.com/file?signature=opaque").hostname, "release-assets.githubusercontent.com");
  for (const url of ["http://github.com/a", "https://example.invalid/a", "https://user:pass@github.com/a", "file:///tmp/a"])
    failure(() => approvedRedirect(url), "download_redirect_invalid");
  assert.equal(loopbackWebSocket("ws://127.0.0.1:12345/devtools/page/test").port, "12345");
  for (const url of ["ws://0.0.0.0:1234/test", "wss://127.0.0.1:1234/test", "ws://user@127.0.0.1:1234/test", "ws://127.0.0.1:1234/test?secret=x"])
    failure(() => loopbackWebSocket(url), "diagnostic_endpoint_invalid");
});

test("Developer ID, expected team, product identifier and hardened runtime are all required", () => {
  const value = `Identifier=com.programai.desktop\nTeamIdentifier=LH2479Y2F4\nAuthority=Developer ID Application: Example (LH2479Y2F4)\nflags=0x10000(runtime)\nCDHash=${"a".repeat(40)}\n`;
  assert.equal(signatureIdentity(value, pins()), "a".repeat(40));
  for (const invalid of [value.replace("LH2479Y2F4", "WRONGTEAM1"), value.replace("com.programai.desktop", "com.other.app"),
    value.replace("Developer ID Application:", "Apple Development:"), value.replace("(runtime)", "(none)")])
    failure(() => signatureIdentity(invalid, pins()), "signing_identity_mismatch");
});

test("shipping updater parsing rejects feed substitutions, unsafe cache segments and duplicate fields", () => {
  const value = "provider: github\nowner: roberttree\nrepo: Program-ai-desktop-releases\nupdaterCacheDirName: '@program-aidesktop-updater'\n";
  assert.equal(parseUpdaterConfiguration(value).repo, "Program-ai-desktop-releases");
  for (const invalid of [value.replace("provider: github", "provider: generic"), value.replace("roberttree", "other"),
    value.replace("@program-aidesktop-updater", "../outside"), value + "repo: Other\n",
    value + "provider : generic\n", value + '"provider": generic\n', value + "provider: generic # duplicate\n"])
    failure(() => parseUpdaterConfiguration(invalid), "shipping_updater_configuration_invalid");
});

test("quarantine requires recent nonzero Chrome-origin metadata, never a simulated replacement", () => {
  const now = 1800000000000;
  const record = `0083;${Math.floor(now / 1000).toString(16)};Google Chrome;12345678-1234-1234-1234-123456789abc`;
  assert.equal(quarantineRecord(record, now - 1000, now), true);
  for (const invalid of [record.replace("0083", "0000"), record.replace("Google Chrome", "curl"),
    record.replace("12345678-1234-1234-1234-123456789abc", "-".repeat(36))])
    failure(() => quarantineRecord(invalid, now - 1000, now), "genuine_browser_quarantine_unverified");
  failure(() => quarantineRecord(record, now + 120000, now + 120000), "genuine_browser_quarantine_unverified");
});

test("public receipts omit raw logs, paths, secrets and source data and do not assert a build", () => {
  const result = receipt({ flow: "install", arch: "x64", version: "1.0.9", status: "unverified",
    checks: ["native_host", "zip_bytes", "zip_bytes"], code: "ticket_validation_unverified",
    token: "private-token", stderr: "/Users/runner/secret", appContents: "private source" });
  assert.deepEqual(result.checks, ["native_host", "zip_bytes"]);
  assert.equal(result.buildAttestation, false);
  assert.equal(result.providerGeneration, false);
  assert.doesNotMatch(JSON.stringify(result), /private-token|Users|private source/);
  failure(() => receipt({ ...result, checks: ["arbitrary-private-value"] }), "receipt_invalid");
});

function zip(entries) {
  const local = [], central = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name), data = Buffer.from(entry.data ?? "");
    const header = Buffer.alloc(30); header.writeUInt32LE(0x04034b50);
    header.writeUInt32LE(data.length, 18); header.writeUInt32LE(data.length, 22); header.writeUInt16LE(name.length, 26);
    const directory = Buffer.alloc(46); directory.writeUInt32LE(0x02014b50);
    directory.writeUInt32LE(data.length, 20); directory.writeUInt32LE(data.length, 24); directory.writeUInt16LE(name.length, 28);
    directory.writeUInt32LE(((entry.mode ?? 0x81a4) << 16) >>> 0, 38); directory.writeUInt32LE(offset, 42);
    local.push(header, name, data); central.push(directory, name); offset += header.length + name.length + data.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}

test("archive preflight accepts bounded bundle paths and framework symlinks without extracting them", () => {
  assert.equal(validateZipArchive(zip([
    { name: "Program AI Desktop.app/Contents/Info.plist", data: "fixture" },
    { name: "Program AI Desktop.app/Contents/Frameworks/Example.framework/Versions/Current", data: "A", mode: 0xa1ff },
  ])), 2);
});

test("archive preflight rejects traversal, duplicate case paths, mismatched local headers and escaping symlinks before extraction", () => {
  for (const entries of [
    [{ name: "../outside", data: "bad" }],
    [{ name: "Program AI Desktop.app/Contents/a" }, { name: "Program AI Desktop.app/Contents/A" }],
  ]) failure(() => validateZipArchive(zip(entries)), "archive_paths_invalid");
  for (const target of ["/private/tmp/outside", "../../../../../../outside"]) failure(() => validateZipArchive(zip([
    { name: "Program AI Desktop.app/Contents/link", data: target, mode: 0xa1ff },
  ])), "archive_link_escape");
  const mismatch = zip([{ name: "Program AI Desktop.app/Contents/file", data: "ok" }]);
  mismatch[30] ^= 1;
  failure(() => validateZipArchive(mismatch), "archive_structure_invalid");
  failure(() => validateZipArchive(Buffer.from("not a zip")), "archive_structure_invalid");
});

test("archive preflight resolves forward symlink chains before parent traversal and bounds cycles", () => {
  failure(() => validateZipArchive(zip([
    { name: "Program AI Desktop.app/Contents/through/file", data: "never extracted" },
    { name: "Program AI Desktop.app/Contents/through", data: "alias/../../outside", mode: 0xa1ff },
    { name: "Program AI Desktop.app/Contents/alias", data: "../root-directory", mode: 0xa1ff },
  ])), "archive_link_escape");
  failure(() => validateZipArchive(zip([
    { name: "Program AI Desktop.app/Contents/loop", data: "loop", mode: 0xa1ff },
  ])), "archive_link_cycle");
  assert.equal(validateZipArchive(zip([
    { name: "Program AI Desktop.app/Contents/Frameworks/Test.framework/Test", data: "Versions/Current/Test", mode: 0xa1ff },
    { name: "Program AI Desktop.app/Contents/Frameworks/Test.framework/Versions/Current", data: "A", mode: 0xa1ff },
    { name: "Program AI Desktop.app/Contents/Frameworks/Test.framework/Versions/A/Test", data: "fixture" },
  ])), 3);
});

test("live context entrypoint has no injectable facts or host bypass", async () => {
  const source = await readFile(new URL("./runtime.mjs", import.meta.url), "utf8");
  assert.match(source, /export async function requireCiContext\(pins\)/);
  assert.match(source, /const account = userInfo\(\)/);
  assert.match(source, /sysctl\.proc_translated/);
  assert.doesNotMatch(source, /SKIP_CI|ALLOW_LOCAL|BYPASS|process\.env\.CI\s*=/);
});
