import { createDecipheriv, createHash } from "node:crypto";
import { gunzipSync, inflateRawSync, inflateSync } from "node:zlib";

import type {
  ConvertNumberInput,
  ConvertNumberResult,
  DecodeStep,
} from "../../domain/native/byteDecoding.js";
import { shannonEntropy } from "../triage/binaryTriageAnalysis.js";

/** A step failed for a reason the caller can act on, such as a wrong key. */
export class DecodeStepFailure extends Error {}

const STANDARD_BASE64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const MAGIC: readonly (readonly [string, readonly number[], number?])[] = [
  ["gzip", [0x1f, 0x8b]],
  ["zlib", [0x78, 0x9c]],
  ["zlib", [0x78, 0x01]],
  ["zlib", [0x78, 0xda]],
  ["zip", [0x50, 0x4b, 0x03, 0x04]],
  ["7z", [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]],
  ["rar", [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]],
  ["bzip2", [0x42, 0x5a, 0x68]],
  ["xz", [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]],
  ["elf", [0x7f, 0x45, 0x4c, 0x46]],
  ["pe/dos-mz", [0x4d, 0x5a]],
  ["mach-o", [0xcf, 0xfa, 0xed, 0xfe]],
  ["mach-o", [0xce, 0xfa, 0xed, 0xfe]],
  ["mach-o", [0xfe, 0xed, 0xfa, 0xcf]],
  ["java-class-or-fat-mach-o", [0xca, 0xfe, 0xba, 0xbe]],
  ["dex", [0x64, 0x65, 0x78, 0x0a]],
  ["wasm", [0x00, 0x61, 0x73, 0x6d]],
  ["png", [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]],
  ["jpeg", [0xff, 0xd8, 0xff]],
  ["gif", [0x47, 0x49, 0x46, 0x38]],
  ["pdf", [0x25, 0x50, 0x44, 0x46, 0x2d]],
  ["ole-compound", [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]],
  ["sqlite", [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66]],
  ["lua-bytecode", [0x1b, 0x4c, 0x75, 0x61]],
  ["shell-script", [0x23, 0x21]],
];

/** Name the container or file type suggested by leading magic bytes. */
export const detectMagic = (bytes: Uint8Array): string | null => {
  for (const [name, prefix, at = 0] of MAGIC)
    if (
      bytes.length >= at + prefix.length &&
      prefix.every((value, index) => bytes[at + index] === value)
    )
      return name;
  return null;
};

export const printableRatio = (bytes: Uint8Array): number => {
  if (bytes.length === 0) return 0;
  let printable = 0;
  for (const byte of bytes)
    if (
      (byte >= 0x20 && byte <= 0x7e) ||
      byte === 0x09 ||
      byte === 0x0a ||
      byte === 0x0d
    )
      printable++;
  return Math.round((printable / bytes.length) * 10000) / 10000;
};

export const byteFacts = (bytes: Uint8Array) => ({
  bytes: bytes.length,
  sha256: createHash("sha256").update(bytes).digest("hex"),
  entropy: shannonEntropy(bytes),
  printable_ratio: printableRatio(bytes),
  magic: detectMagic(bytes),
});

const decodeWithAlphabet = (text: string, alphabet: string): Buffer => {
  const lookup = new Map([...alphabet].map((char, index) => [char, index]));
  const cleaned = text.replace(/[\s=]/g, "");
  const output: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of cleaned) {
    const value = lookup.get(char);
    if (value === undefined)
      throw new DecodeStepFailure(
        `Character ${JSON.stringify(char)} is not in the base64 alphabet.`,
      );
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >> bits) & 0xff);
    }
  }
  return Buffer.from(output);
};

const base64Decode = (bytes: Uint8Array, alphabet?: string): Buffer => {
  const text = Buffer.from(bytes).toString("latin1");
  if (alphabet !== undefined) {
    if (new Set(alphabet).size !== 64)
      throw new DecodeStepFailure(
        "Custom alphabet must have 64 distinct characters.",
      );
    return decodeWithAlphabet(text, alphabet);
  }
  const normalized = text
    .replace(/\s/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized))
    throw new DecodeStepFailure("Input is not standard or URL-safe base64.");
  return decodeWithAlphabet(normalized, STANDARD_BASE64);
};

const base32Decode = (bytes: Uint8Array): Buffer => {
  const text = Buffer.from(bytes)
    .toString("latin1")
    .replace(/[\s=]/g, "")
    .toUpperCase();
  const output: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of text) {
    const value = BASE32.indexOf(char);
    if (value < 0)
      throw new DecodeStepFailure(
        `Character ${JSON.stringify(char)} is not base32.`,
      );
    buffer = ((buffer << 5) | value) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >> bits) & 0xff);
    }
  }
  return Buffer.from(output);
};

const hexDecode = (bytes: Uint8Array): Buffer => {
  const text = Buffer.from(bytes)
    .toString("latin1")
    .replace(/\s|0x|\\x|,/gi, "");
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(text))
    throw new DecodeStepFailure(
      "Input is not an even-length hexadecimal string.",
    );
  return Buffer.from(text, "hex");
};

const rc4 = (bytes: Uint8Array, key: Buffer, drop: number): Buffer => {
  if (key.length > 256)
    throw new DecodeStepFailure("RC4 key exceeds 256 bytes.");
  const state = Uint8Array.from({ length: 256 }, (_, index) => index);
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + state[i]! + key[i % key.length]!) & 0xff;
    [state[i], state[j]] = [state[j]!, state[i]!];
  }
  const output = Buffer.alloc(bytes.length);
  let i = 0;
  let j = 0;
  const next = () => {
    i = (i + 1) & 0xff;
    j = (j + state[i]!) & 0xff;
    [state[i], state[j]] = [state[j]!, state[i]!];
    return state[(state[i]! + state[j]!) & 0xff]!;
  };
  for (let index = 0; index < drop; index++) next();
  for (let index = 0; index < bytes.length; index++)
    output[index] = bytes[index]! ^ next();
  return output;
};

const aesDecrypt = (
  bytes: Uint8Array,
  step: Extract<DecodeStep, { op: "aes_decrypt" }>,
): Buffer => {
  const key = Buffer.from(step.key_hex, "hex");
  if (![16, 24, 32].includes(key.length))
    throw new DecodeStepFailure("AES key must be 16, 24 or 32 bytes.");
  const iv =
    step.iv_hex === undefined ? undefined : Buffer.from(step.iv_hex, "hex");
  if (step.mode !== "ecb" && iv?.length !== 16)
    throw new DecodeStepFailure(
      `AES-${step.mode.toUpperCase()} needs a 16-byte iv_hex.`,
    );
  const algorithm = `aes-${key.length * 8}-${step.mode}`;
  const decipher = createDecipheriv(
    algorithm,
    key,
    step.mode === "ecb" ? null : iv!,
  );
  decipher.setAutoPadding(step.mode !== "ctr" && step.padding === "pkcs7");
  try {
    return Buffer.concat([decipher.update(bytes), decipher.final()]);
  } catch (cause) {
    throw new DecodeStepFailure(
      `AES decryption failed (${cause instanceof Error ? cause.message : "unknown"}); the key, IV, mode or padding is probably wrong.`,
    );
  }
};

const inflate = (
  bytes: Uint8Array,
  format: "zlib" | "raw" | "gzip",
  maxBytes: number,
): Buffer => {
  const options = { maxOutputLength: maxBytes };
  try {
    if (format === "gzip") return gunzipSync(bytes, options);
    if (format === "raw") return inflateRawSync(bytes, options);
    return inflateSync(bytes, options);
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : "unknown";
    throw new DecodeStepFailure(
      /maxOutputLength|buffer/i.test(message)
        ? `Decompressed output exceeds max_bytes (${maxBytes}).`
        : `${format} decompression failed: ${message}`,
    );
  }
};

/** Apply one transform; throws DecodeStepFailure for caller-correctable problems. */
export const applyDecodeStep = (
  bytes: Uint8Array,
  step: DecodeStep,
  maxBytes: number,
): Buffer => {
  switch (step.op) {
    case "base64_decode":
      return base64Decode(bytes, step.alphabet);
    case "base32_decode":
      return base32Decode(bytes);
    case "hex_decode":
      return hexDecode(bytes);
    case "xor": {
      const key = Buffer.from(step.key_hex, "hex");
      return Buffer.from(
        bytes.map((byte, index) => byte ^ key[index % key.length]!),
      );
    }
    case "rc4":
      return rc4(bytes, Buffer.from(step.key_hex, "hex"), step.drop);
    case "aes_decrypt":
      return aesDecrypt(bytes, step);
    case "inflate":
      return inflate(bytes, step.format, maxBytes);
    case "reverse":
      return Buffer.from(bytes).reverse();
    case "not":
      return Buffer.from(bytes.map((byte) => ~byte & 0xff));
    case "add":
      return Buffer.from(bytes.map((byte) => (byte + step.value + 256) & 0xff));
    case "rotate_bits": {
      const left = step.direction === "left" ? step.bits : 8 - step.bits;
      return Buffer.from(
        bytes.map((byte) => ((byte << left) | (byte >> (8 - left))) & 0xff),
      );
    }
    case "slice": {
      if (step.offset > bytes.length)
        throw new DecodeStepFailure(
          `Slice offset ${step.offset} is past the end of ${bytes.length} bytes.`,
        );
      const end =
        step.length === undefined ? bytes.length : step.offset + step.length;
      if (end > bytes.length)
        throw new DecodeStepFailure(
          `Slice of ${step.length} bytes at ${step.offset} exceeds ${bytes.length} bytes.`,
        );
      return Buffer.from(bytes.subarray(step.offset, end));
    }
  }
};

/** Printable preview: printable ASCII as-is, everything else as a dot. */
export const previewText = (bytes: Uint8Array): string =>
  Buffer.from(
    bytes.map((byte) => (byte >= 0x20 && byte <= 0x7e ? byte : 0x2e)),
  ).toString("latin1");

const WIDTHS = [8, 16, 32, 64] as const;

const parseInteger = (text: string): bigint => {
  const negative = text.startsWith("-");
  const body = text.replace(/^[+-]/, "").replaceAll("_", "");
  const value = /^0[oO]/.test(body)
    ? BigInt(`0o${body.slice(2)}`)
    : BigInt(body);
  return negative ? -value : value;
};

const asciiOf = (bytes: Buffer): string | null =>
  bytes.every((byte) => byte >= 0x20 && byte <= 0x7e)
    ? bytes.toString("latin1")
    : null;

/**
 * Show one integer in every representation an analyst compares against:
 * signed and unsigned decimal, hex, octal, binary, both byte orders, their
 * ASCII text and the IEEE-754 float with the same bits.
 */
export const convertNumber = (
  input: ConvertNumberInput,
): ConvertNumberResult => {
  let value: bigint;
  let width: (typeof WIDTHS)[number];
  if (input.bytes_hex !== undefined) {
    const bytes = Buffer.from(input.bytes_hex, "hex");
    const fromBytes = WIDTHS.find((bits) => bits / 8 === bytes.length);
    if (fromBytes === undefined)
      throw new DecodeStepFailure(
        "bytes_hex must hold exactly 1, 2, 4 or 8 bytes.",
      );
    if (input.width !== undefined && input.width !== fromBytes)
      throw new DecodeStepFailure(
        `width ${input.width} does not match ${bytes.length} bytes.`,
      );
    width = fromBytes;
    const ordered =
      input.byte_order === "little" ? Buffer.from(bytes).reverse() : bytes;
    value = BigInt(`0x${ordered.toString("hex") || "0"}`);
  } else {
    value = parseInteger(input.value!);
    const minimal = WIDTHS.find((bits) =>
      value < 0n
        ? value >= -(1n << BigInt(bits - 1))
        : value < 1n << BigInt(bits),
    );
    if (minimal === undefined)
      throw new DecodeStepFailure("Value does not fit in 64 bits.");
    width = input.width ?? minimal;
    const limit = 1n << BigInt(width);
    if (value < -(limit >> 1n) || value >= limit)
      throw new DecodeStepFailure(`Value does not fit in ${width} bits.`);
  }
  const modulus = 1n << BigInt(width);
  const unsigned = ((value % modulus) + modulus) % modulus;
  const signed = unsigned >= modulus >> 1n ? unsigned - modulus : unsigned;
  const bigEndian = Buffer.from(
    unsigned.toString(16).padStart(width / 4, "0"),
    "hex",
  );
  const littleEndian = Buffer.from(bigEndian).reverse();
  let float: number | null = null;
  let note: string | null = null;
  if (width === 32 || width === 64) {
    const raw =
      width === 32 ? bigEndian.readFloatBE(0) : bigEndian.readDoubleBE(0);
    if (Number.isFinite(raw)) float = raw;
    else note = Number.isNaN(raw) ? "NaN" : raw > 0 ? "+Infinity" : "-Infinity";
  } else note = "No IEEE-754 interpretation at this width.";
  return {
    width,
    unsigned: unsigned.toString(),
    signed: signed.toString(),
    hex: `0x${unsigned.toString(16).padStart(width / 4, "0")}`,
    octal: `0o${unsigned.toString(8)}`,
    binary: `0b${unsigned.toString(2).padStart(width, "0")}`,
    bytes_little_endian: littleEndian.toString("hex"),
    bytes_big_endian: bigEndian.toString("hex"),
    ascii_little_endian: asciiOf(littleEndian),
    ascii_big_endian: asciiOf(bigEndian),
    float,
    float_note: note,
  };
};
