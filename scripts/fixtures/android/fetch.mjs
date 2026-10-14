import { createHash, randomUUID } from "node:crypto";
import { createReadStream, openAsBlob } from "node:fs";
import { link, mkdir, open, rm, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { BlobReader, Uint8ArrayWriter, ZipReader } from "@zip.js/zip.js";
import { JADX_RELEASE } from "../../../src/android/JadxRelease.ts";
import fixture from "./apidemos.json" with { type: "json" };

const args = process.argv.slice(2);
if (args.length > 1)
  throw new Error("Usage: npm run fixtures:android -- [DIRECTORY]");
const directory = resolve(
  args[0] ??
    fileURLToPath(
      new URL("../../../_reference/apk-integration/", import.meta.url),
    ),
);
await mkdir(directory, { recursive: true });
const hashFile = async (path) => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
};
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** Returns true when an existing file already has the expected digest. */
const verifiedExisting = async (path, expected) => {
  try {
    const digest = await hashFile(path);
    if (digest !== expected)
      throw new Error(
        `Existing ${path} has a different SHA-256; it was not overwritten`,
      );
    console.log(`Verified existing ${path}: ${digest}`);
    return true;
  } catch (cause) {
    if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
      return false;
    throw cause;
  }
};

/** Download to a private temporary file and publish it only after its digest matches. */
const download = async (url, expected, path) => {
  const temporary = `${path}.${randomUUID()}.partial`;
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(300_000) });
    if (!response.ok || response.body === null)
      throw new Error(`Download failed: ${url}: HTTP ${response.status}`);
    const handle = await open(temporary, "wx", 0o600);
    const hash = createHash("sha256");
    try {
      for await (const chunk of response.body) {
        hash.update(chunk);
        await handle.writeFile(chunk);
      }
    } finally {
      await handle.close();
    }
    const digest = hash.digest("hex");
    if (digest !== expected)
      throw new Error(
        `SHA-256 mismatch for ${url}: expected ${expected}, received ${digest}`,
      );
    await link(temporary, path);
    console.log(`Downloaded and verified ${path}: ${digest}`);
  } finally {
    await rm(temporary, { force: true });
  }
};

// Upstream JADX publishes the all-in-one JAR inside its release ZIP. Verify the
// ZIP against the published digest, then the extracted JAR against its own pin.
const jarPath = join(directory, JADX_RELEASE.jar_filename);
if (!(await verifiedExisting(jarPath, JADX_RELEASE.sha256))) {
  const archivePath = join(directory, `jadx-${JADX_RELEASE.version}.zip`);
  if (!(await verifiedExisting(archivePath, JADX_RELEASE.archive_sha256)))
    await download(
      JADX_RELEASE.archive_url,
      JADX_RELEASE.archive_sha256,
      archivePath,
    );
  const reader = new ZipReader(new BlobReader(await openAsBlob(archivePath)), {
    useWebWorkers: false,
  });
  let bytes;
  try {
    const entry = (await reader.getEntries()).find(
      (candidate) => candidate.filename === JADX_RELEASE.archive_entry,
    );
    if (entry === undefined || entry.directory)
      throw new Error(
        `${archivePath} has no ${JADX_RELEASE.archive_entry} entry`,
      );
    bytes = await entry.getData(new Uint8ArrayWriter());
  } finally {
    await reader.close();
  }
  const digest = sha256(bytes);
  if (digest !== JADX_RELEASE.sha256)
    throw new Error(
      `SHA-256 mismatch for ${JADX_RELEASE.archive_entry}: expected ${JADX_RELEASE.sha256}, received ${digest}`,
    );
  const temporary = `${jarPath}.${randomUUID()}.partial`;
  try {
    await writeFile(temporary, bytes, { flag: "wx", mode: 0o600 });
    await link(temporary, jarPath);
  } finally {
    await rm(temporary, { force: true });
  }
  console.log(`Extracted and verified ${jarPath}: ${digest}`);
}

const apkPath = join(directory, fixture.filename);
if (!(await verifiedExisting(apkPath, fixture.sha256)))
  await download(fixture.url, fixture.sha256, apkPath);
