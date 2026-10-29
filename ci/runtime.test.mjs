import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  PUBLIC_REPOSITORY, VerificationFailure, approvedRedirect, loopbackWebSocket, parseUpdaterConfiguration,
  quarantineRecord, receipt, signatureIdentity, validateArtifact, validateCiFacts, validateMachOInventory, validatePins, validateZipArchive,
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

function nativeInventory(arch = "arm64") {
  const directory = (cpu) => `Contents/Resources/app.asar.unpacked/node_modules/@msgpackr-extract/msgpackr-extract-darwin-${cpu}`;
  return { arch, version: "1.0.9", files: [
    { relativePath: "Contents/MacOS/Program AI Desktop", slices: arch === "x64" ? "x86_64" : "arm64" },
    { relativePath: "Contents/Resources/sidecar", slices: arch === "x64" ? "x86_64" : "arm64" },
    ...["arm64", "x64"].map((cpu) => ({ relativePath: `${directory(cpu)}/node.napi.glibc.node`, slices: cpu === "x64" ? "x86_64" : "arm64" })),
  ], resources: [
    { cpu: "arm64", metadata: { name: "@msgpackr-extract/msgpackr-extract-darwin-arm64", version: "3.0.4", os: ["darwin"], cpu: ["arm64"] },
      metadataSha256: "115e306fbd59af670a4e85f5cc41900d90344211e65d6a91122c018132df48d6",
      binarySha256: arch === "arm64" ? "09faedccf609dde6fb72ca7d58a15e7e8d0baa3750a7bba26cf21e9119014745" : "c16822ba903aea8fa2d137573104f2bae2052b663f991324bac4f65c0d60e0d9" },
    { cpu: "x64", metadata: { name: "@msgpackr-extract/msgpackr-extract-darwin-x64", version: "3.0.4", os: ["darwin"], cpu: ["x64"] },
      metadataSha256: "753a3d68c775279b70dd7b5dc7c6868f9832d4d2090a8d428c98342b99989483",
      binarySha256: arch === "arm64" ? "fc5e0de17cd6dd5ba7ce4043ee39ae9f3b278e7830d2d16e38aef51fc76a01e8" : "4ae10898c6468be2b2a59592541182bf28b7857404c02e64c92f53659a22d7ea" },
  ], loaders: {
    "node_modules/msgpackr-extract/index.js": "a2b9244e83810de461c09f0cd3629899619bf145a40bc05af44553faf40b9ff5",
    "node_modules/node-gyp-build-optional-packages/index.js": "a7ed0d5ae218a19bdbdf15a590d0893790ddf536313b66a787554693cfaae078",
    "node_modules/node-gyp-build-optional-packages/node-gyp-build.js": "21145626bbb3122baf79f196087f05d6f1eeb7b9c65c037ced6940c5c6113440",
  } };
}

test("architecture policy permits only the exact paired, pinned conditional msgpackr resources", () => {
  assert.equal(validateMachOInventory(nativeInventory("arm64")), true);
  assert.equal(validateMachOInventory(nativeInventory("x64")), true);
  for (const arch of ["arm64", "x64"]) {
    const previous = nativeInventory(arch); previous.version = "1.0.8";
    previous.resources[0].binarySha256 = arch === "arm64" ? "f4f350b4fcbadd64759f639989e42de84cc099658f79817311fd11479810c56f" : "d916b8c89dcfb91d0fe66281a7b33fbe453b182eb6a4759b40aec0b3d4464450";
    previous.resources[1].binarySha256 = arch === "arm64" ? "5647133ba13f3046bd2fd4550f75a603e43f535c23f33d1bea0f011f4f1f8af9" : "b87080295249b4863652366929a54fa1d198058978a8414194e88d8ad843532f";
    assert.equal(validateMachOInventory(previous), true);
  }
  const unreviewed = nativeInventory(); unreviewed.version = "1.0.10";
  failure(() => validateMachOInventory(unreviewed), "optional_resource_version_unreviewed");
  const crossVersion = nativeInventory(); crossVersion.version = "1.0.8";
  failure(() => validateMachOInventory(crossVersion), "optional_resource_hash_mismatch");
});

test("main, sidecar, helpers and all other native files remain exact thin target architecture", () => {
  for (const index of [0, 1]) for (const slices of ["x86_64", "arm64 x86_64", "arm64 arm64", "arm64 unknown", ""]) {
    const value = nativeInventory(); value.files[index].slices = slices;
    failure(() => validateMachOInventory(value), "bundle_architecture_mismatch");
  }
  const other = nativeInventory();
  other.files.push({ relativePath: "Contents/Resources/unknown.node", slices: "x86_64" });
  failure(() => validateMachOInventory(other), "bundle_architecture_mismatch");
});

test("conditional addons reject wrong path, declared slices, missing native pair and duplicate resource facts", () => {
  const path = nativeInventory(); path.files[3].relativePath += ".other";
  failure(() => validateMachOInventory(path), "bundle_architecture_mismatch");
  for (const slices of ["arm64", "arm64 x86_64", "x86_64 x86_64", "x86_64 unknown"]) {
    const value = nativeInventory(); value.files[3].slices = slices;
    failure(() => validateMachOInventory(value), "bundle_architecture_mismatch");
  }
  const missingNative = nativeInventory(); missingNative.files.splice(2, 1);
  failure(() => validateMachOInventory(missingNative), "optional_resource_pair_missing");
  const missingOther = nativeInventory(); missingOther.resources.pop();
  failure(() => validateMachOInventory(missingOther), "optional_resource_pair_missing");
  const duplicate = nativeInventory(); duplicate.resources[1] = duplicate.resources[0];
  failure(() => validateMachOInventory(duplicate), "optional_resource_pair_missing");
});

test("conditional resources require exact reviewed metadata, per-bundle binary hashes and loader hashes", () => {
  for (const patch of [{ name: "other" }, { version: "3.0.5" }, { os: ["linux"] }, { cpu: ["x64"] }, { cpu: ["arm64", "x64"] }]) {
    const value = nativeInventory(); Object.assign(value.resources[0].metadata, patch);
    failure(() => validateMachOInventory(value), "optional_resource_metadata_mismatch");
  }
  const metadata = nativeInventory(); metadata.resources[0].metadataSha256 = hash;
  failure(() => validateMachOInventory(metadata), "optional_resource_metadata_mismatch");
  const binary = nativeInventory(); binary.resources[0].binarySha256 = nativeInventory("x64").resources[0].binarySha256;
  failure(() => validateMachOInventory(binary), "optional_resource_hash_mismatch");
  const loader = nativeInventory(); loader.loaders["node_modules/node-gyp-build-optional-packages/node-gyp-build.js"] = hash;
  failure(() => validateMachOInventory(loader), "optional_resource_loader_mismatch");
  const missing = nativeInventory(); delete missing.loaders["node_modules/msgpackr-extract/index.js"];
  failure(() => validateMachOInventory(missing), "optional_resource_loader_mismatch");
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
