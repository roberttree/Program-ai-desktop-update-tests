import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { appendFile, lstat, mkdir, open, readFile, readdir, realpath } from "node:fs/promises";
import { homedir, userInfo } from "node:os";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { inflateRawSync } from "node:zlib";

export const PUBLIC_REPOSITORY = "roberttree/Program-ai-desktop-update-tests";
const RELEASE_REPOSITORY = "roberttree/Program-ai-desktop-releases";
const OWNER_ID = "88110976";
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const FRAME_LIMIT = 2 * 1024 * 1024;

export class VerificationFailure extends Error {
  constructor(kind, code) {
    if (!["failed", "unverified"].includes(kind) || !/^[a-z][a-z0-9_]{0,63}$/.test(code)) {
      throw new TypeError("Invalid fixed verification category");
    }
    super(code);
    this.name = "VerificationFailure";
    this.kind = kind;
    this.code = code;
  }
}

export function check(condition, code, kind = "unverified") {
  if (!condition) throw new VerificationFailure(kind, code);
}

export function validateCiFacts(facts, requestedArch) {
  const env = facts.env;
  check(["arm64", "x64"].includes(requestedArch), "unsupported_architecture");
  check(
    facts.platform === "darwin" && facts.arch === requestedArch && facts.hardwareArch === requestedArch &&
    facts.translated === false && facts.home === "/Users/runner" && facts.accountHome === "/Users/runner" &&
    facts.username === "runner" && facts.uid > 0 && env.CI === "true" && env.GITHUB_ACTIONS === "true" &&
    env.RUNNER_ENVIRONMENT === "github-hosted" && env.RUNNER_OS === "macOS" &&
    env.RUNNER_ARCH === (requestedArch === "arm64" ? "ARM64" : "X64") &&
    env.GITHUB_REPOSITORY === PUBLIC_REPOSITORY && env.GITHUB_REF === "refs/heads/main" &&
    env.GITHUB_EVENT_NAME === "workflow_dispatch" && env.GITHUB_ACTOR_ID === OWNER_ID &&
    env.GITHUB_TRIGGERING_ACTOR === "roberttree" && /^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID ?? "") &&
    /^[a-f0-9]{40}$/.test(env.GITHUB_SHA ?? ""),
    "fresh_native_public_ci_required",
  );
  return requestedArch;
}

export async function requireCiContext(pins) {
  // There is deliberately no test flag, environment override, or injected host
  // probe. Pure tests exercise validateCiFacts; the live entrypoint probes this OS.
  check(process.platform === "darwin", "fresh_native_public_ci_required");
  const account = userInfo();
  const hardware = await run("/usr/sbin/sysctl", ["-in", "hw.optional.arm64"]);
  const translated = await run("/usr/sbin/sysctl", ["-in", "sysctl.proc_translated"]);
  check(["", "0", "1"].includes(hardware.stdout.trim()), "hardware_probe_unverified");
  check(["", "0", "1"].includes(translated.stdout.trim()), "hardware_probe_unverified");
  const arch = process.env.VERIFY_ARCH;
  validateCiFacts({
    env: process.env,
    platform: process.platform,
    arch: process.arch,
    hardwareArch: hardware.stdout.trim() === "1" ? "arm64" : "x64",
    translated: translated.stdout.trim() === "1",
    home: homedir(), accountHome: account.homedir, username: account.username, uid: account.uid,
  }, arch);
  check(pins.repository === PUBLIC_REPOSITORY, "candidate_repository_invalid");
  const origin = (await run("git", ["config", "--get", "remote.origin.url"])).stdout.trim();
  check([
    `https://github.com/${PUBLIC_REPOSITORY}`,
    `https://github.com/${PUBLIC_REPOSITORY}.git`,
    `git@github.com:${PUBLIC_REPOSITORY}.git`,
  ].includes(origin), "checkout_repository_invalid");
  const head = (await run("git", ["rev-parse", "HEAD"])).stdout.trim();
  check(head === process.env.GITHUB_SHA, "checkout_revision_invalid");
  return Object.freeze({ arch, home: account.homedir, version: pins.version });
}

export function validateArtifact(artifact, arch, extension, version) {
  check(artifact && typeof artifact === "object", "artifact_pin_invalid");
  check(artifact.name === `Program-AI-Desktop-mac-${arch}.${extension}`, "artifact_pin_invalid");
  check(/^[a-f0-9]{64}$/.test(artifact.sha256 ?? "") && Number.isSafeInteger(artifact.bytes) &&
    artifact.bytes > 0 && artifact.bytes <= MAX_ARTIFACT_BYTES, "artifact_pin_invalid");
  let url;
  try { url = new URL(artifact.url); } catch { throw new VerificationFailure("unverified", "artifact_url_invalid"); }
  check(url.protocol === "https:" && url.hostname === "github.com" && !url.port && !url.username &&
    !url.password && !url.search && !url.hash &&
    [PUBLIC_REPOSITORY, RELEASE_REPOSITORY].some((repo) =>
      url.pathname === `/${repo}/releases/download/v${version}/${artifact.name}`), "artifact_url_invalid");
  return artifact;
}

export function validatePins(pins) {
  check(pins?.schemaVersion === 1 && pins.repository === PUBLIC_REPOSITORY && pins.version === "1.0.9" &&
    pins.baseVersion === "1.0.8" && pins.teamId === "LH2479Y2F4" && pins.bundleId === "com.programai.desktop",
    "candidate_identity_invalid");
  check(pins.source?.repository === "roberttree/Program-ai-desktop" &&
    /^[a-f0-9]{40}$/.test(pins.source.commit ?? "") && /^[a-f0-9]{40}$/.test(pins.source.tagObject ?? "") &&
    pins.source.tag === `program-ai-desktop-v${pins.version}`, "candidate_source_invalid");
  for (const arch of ["arm64", "x64"]) {
    const artifacts = pins.artifacts?.[arch];
    check(artifacts, "artifact_pin_invalid");
    validateArtifact(artifacts.dmg, arch, "dmg", pins.version);
    validateArtifact(artifacts.zip, arch, "zip", pins.version);
    validateArtifact(artifacts.zipBlockmap, arch, "zip.blockmap", pins.version);
    validateArtifact(artifacts.baseZip, arch, "zip", pins.baseVersion);
  }
  return pins;
}

export async function loadPins(filename = new URL("./candidate.json", import.meta.url)) {
  const bytes = await readFile(filename);
  check(bytes.length > 0 && bytes.length <= 32768, "candidate_file_invalid");
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { throw new VerificationFailure("unverified", "candidate_file_invalid"); }
  return validatePins(value);
}

export async function run(file, args, options = {}) {
  const { timeoutMs = 120000, maxBytes = 1024 * 1024, allowFailure = false,
    code = "command_failed", kind = "unverified", env = process.env } = options;
  const result = await new Promise((resolve) => {
    execFile(file, args, { timeout: timeoutMs, maxBuffer: maxBytes, encoding: "utf8", windowsHide: true, env },
      (error, stdout, stderr) => resolve({
        stdout: stdout ?? "", stderr: stderr ?? "", exitCode: error ? (Number.isInteger(error.code) ? error.code : null) : 0,
        signal: error?.signal ?? null, timedOut: error?.killed === true,
      }));
  });
  if (!allowFailure && result.exitCode !== 0) throw new VerificationFailure(kind, code);
  return result;
}

export function applicationEnvironment() {
  const names = ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "DISPLAY", "XPC_FLAGS", "XPC_SERVICE_NAME", "__CF_USER_TEXT_ENCODING"];
  return Object.fromEntries(names.flatMap((name) => typeof process.env[name] === "string" ? [[name, process.env[name]]] : []));
}

export async function sha256File(filename) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest("hex");
}

export function approvedRedirect(value) {
  let url;
  try { url = new URL(value); } catch { throw new VerificationFailure("unverified", "download_redirect_invalid"); }
  check(url.protocol === "https:" && !url.username && !url.password && !url.port && !url.hash &&
    ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"].includes(url.hostname),
    "download_redirect_invalid");
  return url;
}

export async function downloadPinned(artifact, destination) {
  let current = approvedRedirect(artifact.url);
  for (let hop = 0; hop < 5; hop++) {
    const response = await fetch(current, { redirect: "manual", signal: AbortSignal.timeout(10 * 60 * 1000) });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const next = response.headers.get("location");
      await response.body?.cancel();
      check(next, "download_redirect_invalid");
      current = approvedRedirect(new URL(next, current));
      continue;
    }
    check(response.ok && response.body && Number(response.headers.get("content-length") ?? 0) <= artifact.bytes,
      "pinned_download_unavailable");
    let bytes = 0;
    const hash = createHash("sha256");
    const counter = new Transform({ transform(chunk, _encoding, callback) {
      bytes += chunk.length;
      if (bytes > artifact.bytes || bytes > MAX_ARTIFACT_BYTES) return callback(new VerificationFailure("failed", "artifact_size_mismatch"));
      hash.update(chunk);
      callback(null, chunk);
    } });
    await pipeline(Readable.fromWeb(response.body), counter, createWriteStream(destination, { flags: "wx", mode: 0o600 }));
    check(bytes === artifact.bytes && hash.digest("hex") === artifact.sha256, "artifact_hash_mismatch", "failed");
    return destination;
  }
  throw new VerificationFailure("unverified", "download_redirect_limit");
}

export async function assertAbsent(filename) {
  const existing = await lstat(filename).catch((error) => {
    if (error.code === "ENOENT") return undefined;
    throw new VerificationFailure("unverified", "fresh_state_probe_failed");
  });
  check(!existing, "preexisting_installation_or_state");
}

export async function ensureFreshHost(pins) {
  for (const filename of [
    "/Applications/Program AI Desktop.app",
    path.join(homedir(), "Library/Application Support", pins.bundleId),
    path.join(homedir(), "Library/Caches/program-ai-desktop-updater"),
    path.join(homedir(), "Library/Caches/@program-aidesktop-updater"),
  ]) await assertAbsent(filename);
}

export function validateZipArchive(input) {
  const bytes = Buffer.from(input);
  check(bytes.length >= 22 && bytes.length <= MAX_ARTIFACT_BYTES, "archive_structure_invalid", "failed");
  let end = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65557); offset--) {
    if (bytes.readUInt32LE(offset) === 0x06054b50 && offset + 22 + bytes.readUInt16LE(offset + 20) === bytes.length) { end = offset; break; }
  }
  check(end >= 0, "archive_structure_invalid", "failed");
  const count = bytes.readUInt16LE(end + 10);
  const length = bytes.readUInt32LE(end + 12);
  let cursor = bytes.readUInt32LE(end + 16);
  const directoryEnd = cursor + length;
  check(bytes.readUInt16LE(end + 4) === 0 && bytes.readUInt16LE(end + 6) === 0 &&
    bytes.readUInt16LE(end + 8) === count && count > 0 && count <= 30000 && directoryEnd === end,
    "archive_structure_invalid", "failed");
  const names = new Set();
  const entries = [];
  const links = new Map();
  const pathKey = (name) => name.normalize("NFC").toLowerCase().replace(/\/$/, "");
  for (let index = 0; index < count; index++) {
    check(cursor + 46 <= end && bytes.readUInt32LE(cursor) === 0x02014b50, "archive_structure_invalid", "failed");
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const next = cursor + 46 + nameLength + extraLength + commentLength;
    check(next <= end, "archive_structure_invalid", "failed");
    const nameBytes = bytes.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = nameBytes.toString("utf8");
    const key = pathKey(name);
    check(name && !/[\\\u0000-\u001f\u007f]/.test(name) && !name.startsWith("/") &&
      !name.replace(/\/$/, "").split("/").some((part) => !part || part === "." || part === "..") && !names.has(key) &&
      (name.startsWith("Program AI Desktop.app/") || name.startsWith("__MACOSX/")), "archive_paths_invalid", "failed");
    check(nameBytes.equals(Buffer.from(name, "utf8")), "archive_paths_invalid", "failed");
    names.add(key);
    entries.push(name);
    const local = bytes.readUInt32LE(cursor + 42);
    const compressed = bytes.readUInt32LE(cursor + 20);
    const uncompressed = bytes.readUInt32LE(cursor + 24);
    check(local + 30 <= bytes.length && bytes.readUInt32LE(local) === 0x04034b50, "archive_structure_invalid", "failed");
    const localNameLength = bytes.readUInt16LE(local + 26);
    const data = local + 30 + localNameLength + bytes.readUInt16LE(local + 28);
    check(data + compressed <= directoryEnd - length &&
      nameBytes.equals(bytes.subarray(local + 30, local + 30 + localNameLength)), "archive_structure_invalid", "failed");
    if ((bytes.readUInt32LE(cursor + 38) >>> 16 & 0xf000) === 0xa000) {
      check(uncompressed > 0 && uncompressed <= 4096 && compressed <= 65536, "archive_link_invalid", "failed");
      const payload = bytes.subarray(data, data + compressed);
      const method = bytes.readUInt16LE(cursor + 10);
      check(method === 0 || method === 8, "archive_link_invalid", "failed");
      let target, targetBytes;
      try {
        targetBytes = method === 0 ? payload : inflateRawSync(payload, { maxOutputLength: 4096 });
        target = targetBytes.toString("utf8");
      }
      catch { throw new VerificationFailure("failed", "archive_link_invalid"); }
      check(target && !target.startsWith("/") && !/[\\\u0000-\u001f\u007f]/.test(target) &&
        targetBytes.length === uncompressed && targetBytes.equals(Buffer.from(target, "utf8")),
        "archive_link_escape", "failed");
      links.set(key, target);
    }
    cursor = next;
  }
  check(cursor === directoryEnd, "archive_structure_invalid", "failed");
  // Resolve every entry through the complete virtual symlink graph before
  // ditto can create anything. Lexical normalization alone misses a parent
  // symlink followed by '..', including forward-declared symlinks.
  for (const name of entries) {
    const root = name.startsWith("__MACOSX/") ? "__MACOSX" : "Program AI Desktop.app";
    const pending = name.split("/");
    const resolved = [];
    let steps = 0;
    while (pending.length) {
      check(++steps <= 1024, "archive_link_cycle", "failed");
      const component = pending.shift();
      if (!component || component === ".") continue;
      if (component === "..") {
        check(resolved.length > 1, "archive_link_escape", "failed");
        resolved.pop();
        continue;
      }
      resolved.push(component);
      check(pathKey(resolved[0]) === pathKey(root), "archive_link_escape", "failed");
      const target = links.get(pathKey(resolved.join("/")));
      if (target !== undefined) {
        resolved.pop();
        pending.unshift(...target.split("/"));
      }
    }
    check(resolved.length > 0, "archive_link_escape", "failed");
  }
  return names.size;
}

export async function extractZip(zip, destination) {
  await assertAbsent(destination);
  // Validate central/local paths and Unix symlink targets before native
  // extraction. Hash pins do not justify writes outside the disposable root.
  validateZipArchive(await readFile(zip));
  await mkdir(destination, { mode: 0o700 });
  await run("/usr/bin/ditto", ["-x", "-k", zip, destination]);
  const app = path.join(destination, "Program AI Desktop.app");
  check((await lstat(app)).isDirectory() && !(await lstat(app)).isSymbolicLink(), "archive_app_invalid", "failed");
  return app;
}

export function signatureIdentity(text, pins, runtime = true) {
  check(text.includes(`Identifier=${pins.bundleId}\n`) && text.includes(`TeamIdentifier=${pins.teamId}\n`) &&
    /Authority=Developer ID Application:/.test(text) && (!runtime || /flags=.*\bruntime\b/.test(text)),
    "signing_identity_mismatch", "failed");
  const cdhash = /^CDHash=([a-f0-9]{40,64})$/m.exec(text)?.[1];
  check(cdhash, "signature_hash_missing", "failed");
  return cdhash;
}

export function staplerObservation(result) {
  const exitCode = Number.isInteger(result.exitCode) && result.exitCode >= 0 && result.exitCode <= 255 ? result.exitCode : null;
  const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.slice(0, 131072);
  if (exitCode === 0) return { exitCode, category: "validated" };
  if (/does not have a ticket stapled to it/i.test(text)) return { exitCode, category: "ticket_missing" };
  // sysexits: invalid data, missing/invalid input, and revoked permission are
  // never retried, even if a diagnostic also contains a network error string.
  if ([65, 66, 77].includes(exitCode) || /ticket (?:has been )?revoked|ticket data is invalid/i.test(text))
    return { exitCode, category: "ticket_rejected" };
  // Only documented NSURL transport errors qualify. Exit 68 is ambiguous
  // (unnotarized OR unexpected service response), not evidence of a network fault.
  const errors = [...text.matchAll(/NSURLErrorDomain\s+Code\s*=\s*(-\d+)\b/g)];
  if (!result.timedOut && errors.length > 0 && errors.every((match) => [-1001, -1003, -1004, -1005, -1006, -1009].includes(Number(match[1]))))
    return { exitCode, category: "transient_network" };
  return { exitCode, category: "unknown" };
}

export function staplerAction(observation, attempt) {
  check(Number.isInteger(attempt) && attempt >= 1 && attempt <= 3 &&
    ["validated", "ticket_missing", "ticket_rejected", "transient_network", "unknown"].includes(observation.category), "stapler_observation_invalid");
  if (observation.category === "validated") return { done: true };
  if (observation.category === "transient_network" && attempt < 3) return { retryAfterMs: attempt === 1 ? 2000 : 5000 };
  const category = observation.category;
  return { kind: ["ticket_missing", "ticket_rejected"].includes(category) ? "failed" : "unverified",
    code: category === "ticket_missing" ? "stapled_ticket_missing" : category === "ticket_rejected" ? "ticket_validation_rejected" :
      category === "transient_network" ? "ticket_network_unverified" : "ticket_validation_unverified" };
}

export async function validateStaple(filename) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const result = await run("/usr/bin/xcrun", ["stapler", "validate", "-v", filename], { allowFailure: true, maxBytes: 65536 });
    const observation = staplerObservation(result);
    console.log(JSON.stringify({ schemaVersion: 1, check: "stapler_validate", attempt, ...observation }));
    const action = staplerAction(observation, attempt);
    if (action.done) return;
    if (!action.retryAfterMs) throw new VerificationFailure(action.kind, action.code);
    await new Promise((resolve) => setTimeout(resolve, action.retryAfterMs));
  }
}

async function verifyMachOFiles(app, arch, version) {
  const root = await realpath(app);
  const visited = new Set();
  let files = 0;
  const nativeFiles = [];
  async function visit(candidate) {
    const canonical = await realpath(candidate);
    check(canonical === root || canonical.startsWith(root + path.sep), "bundle_symlink_escape", "failed");
    if (visited.has(canonical)) return;
    visited.add(canonical);
    check(++files <= 40000, "bundle_file_limit", "failed");
    const info = await lstat(canonical);
    if (info.isDirectory()) {
      for (const item of await readdir(canonical)) await visit(path.join(canonical, item));
      return;
    }
    if (!info.isFile() || info.size < 4) return;
    const file = await open(canonical, "r");
    const bytes = Buffer.alloc(4);
    try { await file.read(bytes, 0, 4, 0); } finally { await file.close(); }
    if (![0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].includes(bytes.readUInt32BE(0))) return;
    const slices = (await run("/usr/bin/lipo", ["-archs", canonical])).stdout.trim();
    nativeFiles.push({ relativePath: path.relative(root, canonical), slices });
  }
  await visit(root);
  const resources = [];
  for (const cpu of ["arm64", "x64"]) {
    const directory = path.join(root, optionalDirectory(cpu));
    const bytes = await readFile(path.join(directory, "package.json"));
    check(bytes.length <= 4096, "optional_resource_metadata_mismatch", "failed");
    let metadata;
    try { metadata = JSON.parse(bytes.toString("utf8")); }
    catch { throw new VerificationFailure("failed", "optional_resource_metadata_mismatch"); }
    resources.push({ cpu, metadata, metadataSha256: createHash("sha256").update(bytes).digest("hex"),
      binarySha256: await sha256File(path.join(directory, "node.napi.glibc.node")) });
  }
  const loaders = {};
  for (const filename of Object.keys(optionalLoaderPins)) {
    loaders[filename] = createHash("sha256").update(await readAsarResource(path.join(root, "Contents/Resources/app.asar"), filename)).digest("hex");
  }
  validateMachOInventory({ arch, version, files: nativeFiles, resources, loaders });
}

const optionalDirectory = (cpu) => `Contents/Resources/app.asar.unpacked/node_modules/@msgpackr-extract/msgpackr-extract-darwin-${cpu}`;
const optionalResourcePins = {
  arm64: {
    metadata: "115e306fbd59af670a4e85f5cc41900d90344211e65d6a91122c018132df48d6",
    "1.0.8": { arm64: "f4f350b4fcbadd64759f639989e42de84cc099658f79817311fd11479810c56f", x64: "d916b8c89dcfb91d0fe66281a7b33fbe453b182eb6a4759b40aec0b3d4464450" },
    "1.0.9": { arm64: "09faedccf609dde6fb72ca7d58a15e7e8d0baa3750a7bba26cf21e9119014745", x64: "c16822ba903aea8fa2d137573104f2bae2052b663f991324bac4f65c0d60e0d9" },
  },
  x64: {
    metadata: "753a3d68c775279b70dd7b5dc7c6868f9832d4d2090a8d428c98342b99989483",
    "1.0.8": { arm64: "5647133ba13f3046bd2fd4550f75a603e43f535c23f33d1bea0f011f4f1f8af9", x64: "b87080295249b4863652366929a54fa1d198058978a8414194e88d8ad843532f" },
    "1.0.9": { arm64: "fc5e0de17cd6dd5ba7ce4043ee39ae9f3b278e7830d2d16e38aef51fc76a01e8", x64: "4ae10898c6468be2b2a59592541182bf28b7857404c02e64c92f53659a22d7ea" },
  },
};
const optionalLoaderPins = {
  "node_modules/msgpackr-extract/index.js": "a2b9244e83810de461c09f0cd3629899619bf145a40bc05af44553faf40b9ff5",
  "node_modules/node-gyp-build-optional-packages/index.js": "a7ed0d5ae218a19bdbdf15a590d0893790ddf536313b66a787554693cfaae078",
  "node_modules/node-gyp-build-optional-packages/node-gyp-build.js": "21145626bbb3122baf79f196087f05d6f1eeb7b9c65c037ced6940c5c6113440",
};

export function validateMachOInventory({ arch, version, files, resources, loaders }) {
  check(["arm64", "x64"].includes(arch), "unsupported_architecture");
  check(["1.0.8", "1.0.9"].includes(version), "optional_resource_version_unreviewed", "failed");
  check(Array.isArray(files) && files.length > 1 && files.length <= 40000,
    "bundle_native_code_missing", "failed");
  const entries = new Map();
  for (const file of files) {
    check(typeof file.relativePath === "string" && !entries.has(file.relativePath), "bundle_native_code_missing", "failed");
    entries.set(file.relativePath, file.slices);
    const cpu = ["arm64", "x64"].find((item) => file.relativePath === `${optionalDirectory(item)}/node.napi.glibc.node`);
    check(file.slices === ((cpu ?? arch) === "x64" ? "x86_64" : "arm64"), "bundle_architecture_mismatch", "failed");
  }
  check(entries.has("Contents/MacOS/Program AI Desktop"), "bundle_native_code_missing", "failed");
  check(Array.isArray(resources) && resources.length === 2 && new Set(resources.map((item) => item.cpu)).size === 2,
    "optional_resource_pair_missing", "failed");
  // These are conditional third-party resources, not executable architecture
  // acceptance: the reviewed loader selects os.arch()/os.platform() (its npm
  // override variables are absent from applicationEnvironment). Both pinned
  // packages must exist, and each must exactly match its declared thin CPU.
  // No other opposite-architecture or universal binary is exempted. Native app
  // execution still requires the independent guarded host/process checks.
  for (const cpu of ["arm64", "x64"]) {
    const resource = resources.find((item) => item.cpu === cpu);
    const metadata = resource?.metadata;
    check(entries.has(`${optionalDirectory(cpu)}/node.napi.glibc.node`) && resource,
      "optional_resource_pair_missing", "failed");
    check(metadata?.name === `@msgpackr-extract/msgpackr-extract-darwin-${cpu}` && metadata.version === "3.0.4" &&
      Array.isArray(metadata.os) && metadata.os.length === 1 && metadata.os[0] === "darwin" &&
      Array.isArray(metadata.cpu) && metadata.cpu.length === 1 && metadata.cpu[0] === cpu &&
      resource.metadataSha256 === optionalResourcePins[cpu].metadata, "optional_resource_metadata_mismatch", "failed");
    check(resource.binarySha256 === optionalResourcePins[cpu][version][arch], "optional_resource_hash_mismatch", "failed");
  }
  check(loaders && Object.keys(loaders).length === Object.keys(optionalLoaderPins).length &&
    Object.entries(optionalLoaderPins).every(([name, hash]) => loaders[name] === hash), "optional_resource_loader_mismatch", "failed");
  return true;
}

export async function readAsarResource(filename, resource) {
  check(Object.hasOwn(optionalLoaderPins, resource), "optional_resource_loader_mismatch", "failed");
  const file = await open(filename, "r");
  try {
    const size = (await file.stat()).size;
    const prefix = Buffer.alloc(16);
    check((await file.read(prefix, 0, 16, 0)).bytesRead === 16 && prefix.readUInt32LE(0) === 4,
      "optional_resource_loader_mismatch", "failed");
    const headerSize = prefix.readUInt32LE(4), jsonSize = prefix.readUInt32LE(12);
    check(jsonSize > 0 && jsonSize <= 16 * 1024 * 1024 && headerSize >= jsonSize + 8 && 8 + headerSize <= size,
      "optional_resource_loader_mismatch", "failed");
    const bytes = Buffer.alloc(jsonSize);
    check((await file.read(bytes, 0, jsonSize, 16)).bytesRead === jsonSize, "optional_resource_loader_mismatch", "failed");
    let entry;
    try { entry = JSON.parse(bytes.toString("utf8")); }
    catch { throw new VerificationFailure("failed", "optional_resource_loader_mismatch"); }
    for (const part of resource.split("/")) entry = entry?.files?.[part];
    const offset = Number(entry?.offset);
    check(entry && !entry.unpacked && !entry.link && Number.isSafeInteger(entry.size) && entry.size > 0 && entry.size <= 32768 &&
      typeof entry.offset === "string" && /^\d+$/.test(entry.offset) && Number.isSafeInteger(offset) &&
      offset >= 0 && 8 + headerSize + offset + entry.size <= size, "optional_resource_loader_mismatch", "failed");
    const content = Buffer.alloc(entry.size);
    check((await file.read(content, 0, content.length, 8 + headerSize + offset)).bytesRead === content.length,
      "optional_resource_loader_mismatch", "failed");
    return content;
  } finally { await file.close(); }
}

export function parseUpdaterConfiguration(text) {
  const values = new Map();
  // This intentionally accepts only the flat scalar configuration used by a
  // packaged updater. Do not pretend to parse YAML aliases, duplicate keys,
  // nested objects, tags, or quoted key variants with a partial regex.
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const entry = /^([A-Za-z_][A-Za-z0-9_]*):\s*(?:'([A-Za-z0-9@._/-]+)'|"([A-Za-z0-9@._/-]+)"|([A-Za-z0-9@._/-]+))\s*$/.exec(line);
    check(entry && !values.has(entry[1]), "shipping_updater_configuration_invalid", "failed");
    values.set(entry[1], entry[2] ?? entry[3] ?? entry[4]);
  }
  const field = (name) => {
    check(values.has(name), "shipping_updater_configuration_invalid", "failed");
    return values.get(name);
  };
  const updater = { provider: field("provider"), owner: field("owner"), repo: field("repo"), updaterCacheDirName: field("updaterCacheDirName") };
  check(updater.provider === "github" && updater.owner === "roberttree" && updater.repo === "Program-ai-desktop-releases" &&
    typeof updater.updaterCacheDirName === "string" && /^[A-Za-z0-9@._-]{1,128}$/.test(updater.updaterCacheDirName) &&
    ![".", ".."].includes(updater.updaterCacheDirName), "shipping_updater_configuration_invalid", "failed");
  return updater;
}

export async function verifyApp(appPath, { pins, arch, version = pins.version }) {
  const app = await realpath(appPath);
  const infoResult = await run("/usr/bin/plutil", ["-convert", "json", "-o", "-", path.join(app, "Contents/Info.plist")]);
  let info;
  try { info = JSON.parse(infoResult.stdout); } catch { throw new VerificationFailure("failed", "bundle_info_invalid"); }
  check(info.CFBundleIdentifier === pins.bundleId && info.CFBundleShortVersionString === version &&
    info.CFBundleExecutable === "Program AI Desktop", "bundle_identity_mismatch", "failed");
  const description = await run("/usr/bin/codesign", ["-dvvv", app]);
  const cdhash = signatureIdentity(description.stdout + description.stderr, pins);
  await run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app], { kind: "failed", code: "app_signature_invalid" });
  await run("/usr/sbin/spctl", ["--assess", "--type", "execute", app], { code: "app_gatekeeper_unverified" });
  await validateStaple(app);
  await verifyMachOFiles(app, arch, version);
  const updater = parseUpdaterConfiguration(await readFile(path.join(app, "Contents/Resources/app-update.yml"), "utf8"));
  return { version, cdhash, executable: path.join(app, "Contents/MacOS", info.CFBundleExecutable),
    asarSha256: await sha256File(path.join(app, "Contents/Resources/app.asar")), updater };
}

export async function verifyDmg(dmg, { pins }) {
  await run("/usr/bin/hdiutil", ["verify", dmg], { kind: "failed", code: "dmg_integrity_invalid" });
  const signature = await run("/usr/bin/codesign", ["-dvvv", dmg]);
  check((signature.stdout + signature.stderr).includes(`TeamIdentifier=${pins.teamId}\n`) &&
    /Authority=Developer ID Application:/.test(signature.stdout + signature.stderr), "dmg_signer_mismatch", "failed");
  await run("/usr/bin/codesign", ["--verify", "--strict", dmg], { kind: "failed", code: "dmg_signature_invalid" });
  await run("/usr/sbin/spctl", ["--assess", "--type", "open", "--context", "context:primary-signature", dmg], { code: "dmg_gatekeeper_unverified" });
  await validateStaple(dmg);
}

export async function findOwnedPids(executable) {
  const canonical = await realpath(executable);
  const result = await run("/bin/ps", ["-axo", "pid=,comm="], { maxBytes: 4 * 1024 * 1024 });
  return result.stdout.split("\n").flatMap((line) => {
    const match = /^\s*([1-9][0-9]*)\s+(.+?)\s*$/.exec(line);
    return match && match[2] === canonical ? [Number(match[1])] : [];
  });
}

export async function findOwnedPid(executable) {
  const pids = await findOwnedPids(executable);
  check(pids.length === 1, "native_process_unverified");
  return pids[0];
}

export async function terminateOwned(executable, pid) {
  check(Number.isSafeInteger(pid) && pid > 1 && (await findOwnedPids(executable)).includes(pid), "cleanup_ownership_unverified");
  process.kill(pid, "SIGTERM");
  await waitFor(async () => !(await findOwnedPids(executable)).includes(pid), { timeoutMs: 10000, code: "owned_process_did_not_exit" });
}

export async function unusedPort() {
  const { createServer } = await import("node:net");
  const server = createServer();
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

export async function waitFor(probe, { timeoutMs = 60000, code = "condition_unverified", intervalMs = 250 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { const result = await probe(); if (result) return result; }
    catch (error) { if (error instanceof VerificationFailure && error.kind === "failed") throw error; }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new VerificationFailure("unverified", code);
}

export function loopbackWebSocket(value) {
  let url;
  try { url = new URL(value); } catch { throw new VerificationFailure("unverified", "diagnostic_endpoint_invalid"); }
  check(url.protocol === "ws:" && url.hostname === "127.0.0.1" && /^\d+$/.test(url.port) &&
    !url.username && !url.password && !url.search && !url.hash, "diagnostic_endpoint_invalid");
  return url;
}

export async function verifyListener(port, pid, executable) {
  check(Number.isSafeInteger(port) && port > 0 && port < 65536 && Number.isSafeInteger(pid) && pid > 1, "diagnostic_owner_invalid");
  if (executable) check((await findOwnedPids(executable)).includes(pid), "diagnostic_owner_invalid");
  const result = await run("/usr/sbin/lsof", ["-nP", "-a", "-p", String(pid), `-iTCP:${port}`, "-sTCP:LISTEN", "-F", "n"], { allowFailure: true });
  const names = result.stdout.split("\n").filter((line) => line.startsWith("n"));
  check(result.exitCode === 0 && names.length > 0 && names.every((line) =>
    line === `n127.0.0.1:${port}` || line === `n[::1]:${port}`), "diagnostic_listener_unverified");
}

export async function connectWebSocket(value, { timeoutMs = 20000 } = {}) {
  const url = loopbackWebSocket(value);
  const socket = new WebSocket(url);
  const pending = new Map();
  const listeners = new Map();
  let sequence = 0;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.close(); reject(new VerificationFailure("unverified", "diagnostic_connect_timeout")); }, timeoutMs);
    socket.addEventListener("open", () => { clearTimeout(timer); resolve(); }, { once: true });
    socket.addEventListener("error", () => { clearTimeout(timer); reject(new VerificationFailure("unverified", "diagnostic_connect_failed")); }, { once: true });
  });
  socket.addEventListener("message", (event) => {
    if (typeof event.data !== "string" || event.data.length > FRAME_LIMIT) { socket.close(); return; }
    let message;
    try { message = JSON.parse(event.data); } catch { socket.close(); return; }
    if (message.id && pending.has(message.id)) {
      const request = pending.get(message.id);
      pending.delete(message.id);
      clearTimeout(request.timer);
      if (message.error) request.reject(new VerificationFailure("unverified", "diagnostic_command_failed"));
      else request.resolve(message.result);
    }
    for (const listener of listeners.get(message.method) ?? []) listener(message.params);
  });
  socket.addEventListener("close", () => {
    for (const request of pending.values()) { clearTimeout(request.timer); request.reject(new VerificationFailure("unverified", "diagnostic_closed")); }
    pending.clear();
  });
  return {
    send(method, params = {}, requestTimeoutMs = timeoutMs) {
      check(pending.size < 64 && socket.readyState === WebSocket.OPEN, "diagnostic_request_unavailable");
      return new Promise((resolve, reject) => {
        const id = ++sequence;
        const timer = setTimeout(() => { pending.delete(id); reject(new VerificationFailure("unverified", "diagnostic_command_timeout")); }, requestTimeoutMs);
        pending.set(id, { resolve, reject, timer });
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    onEvent(method, callback) {
      const set = listeners.get(method) ?? new Set();
      set.add(callback); listeners.set(method, set);
      return () => set.delete(callback);
    },
    close() { socket.close(); },
  };
}

export async function connectCdp(port, pid, { timeoutMs = 60000, targetType = "page", executable } = {}) {
  return waitFor(async () => {
    await verifyListener(port, pid, executable);
    const response = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(3000), redirect: "error" });
    check(response.ok, "diagnostic_targets_unavailable");
    const text = await response.text();
    check(text.length < 262144, "diagnostic_targets_invalid");
    const targets = JSON.parse(text);
    const matches = targets.filter((target) => target.type === targetType &&
      typeof target.webSocketDebuggerUrl === "string" && (targetType !== "page" ||
        /^(?:program-ai:\/\/renderer|file:\/\/|about:blank|https:\/\/github\.com\/)/.test(target.url ?? "")));
    check(matches.length === 1, "diagnostic_target_unverified");
    const endpoint = loopbackWebSocket(matches[0].webSocketDebuggerUrl);
    check(endpoint.port === String(port), "diagnostic_owner_invalid");
    const client = await connectWebSocket(endpoint.href);
    return { ...client, target: { type: targetType }, evaluate: (expression, ms = 30000) => evaluate(client, expression, ms) };
  }, { timeoutMs, code: "diagnostic_target_unavailable" });
}

export async function evaluate(client, expression, timeoutMs = 30000) {
  const result = await client.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, timeoutMs);
  check(!result.exceptionDetails && !result.result?.subtype?.includes("error"), "renderer_evaluation_unverified");
  return result.result?.value;
}

export function quarantineRecord(text, startedMs, nowMs = Date.now()) {
  const parts = text.trim().split(";");
  const created = Number.parseInt(parts[1] ?? "", 16) * 1000;
  check(parts.length === 4 && /^[a-f0-9]{4,8}$/i.test(parts[0]) && Number.parseInt(parts[0], 16) !== 0 &&
    /^[a-f0-9]{8,16}$/i.test(parts[1]) && ["Google Chrome", "Chrome"].includes(parts[2]) &&
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(parts[3]) && created >= startedMs - 60000 && created <= nowMs + 60000,
    "genuine_browser_quarantine_unverified");
  return true;
}

const receiptChecks = new Set([
  "native_host", "zip_bytes", "zip_app_signature", "zip_app_ticket", "headed_browser_download", "genuine_quarantine",
  "dmg_bytes", "dmg_signature", "dmg_ticket", "mounted_app", "finder_install", "native_launch", "sidecar_ready",
  "renderer_ready", "signed_out", "local_typing", "update_download", "native_update", "state_preserved",
  "failure_rejected", "recovery_download", "cleanup",
]);
const installPhases = new Set(["preflight", "zip_download", "zip_verify", "browser_preflight", "browser_launch", "browser_connect",
  "browser_navigation", "browser_download", "dmg_verify", "dmg_mount", "mounted_verify", "finder_install", "installed_verify",
  "application_launch", "renderer_connect", "sidecar_ready", "renderer_ready", "local_typing", "completed", "cleanup"]);

export function launchObservation(value) {
  const launcherMode = value?.launcherMode ?? "launch_services";
  check(value && ["browser", "application"].includes(value.context) && Number.isInteger(value.pidCount) && value.pidCount >= 0 && value.pidCount <= 2 &&
    ["not_checked", "ready", "unverified"].includes(value.listener) && ["pending", "succeeded", "failed", "not_used"].includes(value.openStatus) &&
    (value.openExitCode === null || Number.isInteger(value.openExitCode) && value.openExitCode >= 0 && value.openExitCode <= 255) &&
    typeof value.dialogApproved === "boolean" && typeof value.openTimedOut === "boolean" &&
    ["launch_services", "direct_vendor_browser"].includes(launcherMode) &&
    (value.context !== "application" || launcherMode === "launch_services") &&
    (launcherMode === "direct_vendor_browser" ? value.context === "browser" && value.openStatus === "not_used" &&
      ["pending", "spawned", "exited", "error"].includes(value.processStatus) &&
      (value.processExitCode === null || Number.isInteger(value.processExitCode) && value.processExitCode >= 0 && value.processExitCode <= 255) :
      value.openStatus !== "not_used"), "launch_observation_invalid");
  return { context: value.context, launcherMode, pidCount: value.pidCount, listener: value.listener,
    ...(launcherMode === "direct_vendor_browser" ? { processStatus: value.processStatus, processExitCode: value.processExitCode } : {}),
    openStatus: value.openStatus, openExitCode: value.openExitCode, openTimedOut: value.openTimedOut, dialogApproved: value.dialogApproved };
}

export function receipt(value) {
  check(["install", "update"].includes(value.flow) && ["arm64", "x64"].includes(value.arch) &&
    ["passed", "failed", "unverified"].includes(value.status) && /^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(value.version) &&
    Array.isArray(value.checks) && value.checks.length <= 32 && value.checks.every((item) => receiptChecks.has(item)), "receipt_invalid");
  const result = { schemaVersion: 1, flow: value.flow, arch: value.arch, version: value.version,
    status: value.status, checks: [...new Set(value.checks)], buildAttestation: false, providerGeneration: false };
  if (value.code) { check(/^[a-z][a-z0-9_]{0,63}$/.test(value.code), "receipt_invalid"); result.code = value.code; }
  if (value.phase !== undefined) {
    check(value.flow === "install" && installPhases.has(value.phase), "receipt_invalid"); result.phase = value.phase;
  }
  if (value.launch !== undefined) { check(value.flow === "install", "receipt_invalid"); result.launch = launchObservation(value.launch); }
  if (value.browserLaunch !== undefined) {
    check(value.flow === "install" && value.browserLaunch.context === "browser", "receipt_invalid");
    result.browserLaunch = launchObservation(value.browserLaunch);
  }
  if (value.gui !== undefined) {
    check(value.flow === "install" && typeof value.gui.consoleUserIsRunner === "boolean" && typeof value.gui.guiBootstrapAvailable === "boolean" &&
      (value.gui.guiBootstrapExitCode === null || Number.isInteger(value.gui.guiBootstrapExitCode) && value.gui.guiBootstrapExitCode >= 0 && value.gui.guiBootstrapExitCode <= 255), "receipt_invalid");
    result.gui = { consoleUserIsRunner: value.gui.consoleUserIsRunner, guiBootstrapAvailable: value.gui.guiBootstrapAvailable,
      guiBootstrapExitCode: value.gui.guiBootstrapExitCode };
  }
  return result;
}

export async function emitReceipt(value) {
  const result = receipt(value);
  console.log(JSON.stringify(result));
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY,
    `\n### ${result.flow} verification (${result.arch})\n\nOutcome: ${result.status}. Version: ${result.version}.\n\nChecks: ${result.checks.join(", ") || "none"}.\n\nNo provider generation or build attestation is claimed.\n`);
}
