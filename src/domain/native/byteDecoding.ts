import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";
import { analystDirectedTextFindingSchema } from "./binaryTriage.js";

const uint = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const hexBytes = z
  .string()
  .regex(/^(?:[0-9a-fA-F]{2})*$/, "Expected an even-length hexadecimal string")
  .describe("Bytes as hexadecimal, two digits per byte");
const nonEmptyHexBytes = hexBytes.refine((value) => value.length > 0, {
  message: "Expected at least one byte",
});

/** Where the bytes to decode come from. Inline input carries no file identity. */
export const decodeInputSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("hex"), value: hexBytes }),
  z.strictObject({
    kind: z.literal("base64"),
    value: z.string().describe("Standard or URL-safe base64"),
  }),
  z.strictObject({
    kind: z.literal("text"),
    value: z.string(),
    encoding: z.enum(["utf8", "latin1", "utf16le"]).default("utf8"),
  }),
  z.strictObject({
    kind: z.literal("file"),
    path: localPathStringSchema.describe("Absolute path of the file to read"),
    offset: uint.default(0).describe("First byte to read"),
    length: uint
      .optional()
      .describe("Bytes to read from offset; omitted reads to the end"),
  }),
]);

/** One deterministic transform. Steps run in order; the first failure stops the chain. */
export const decodeStepSchema = z.discriminatedUnion("op", [
  z.strictObject({
    op: z.literal("base64_decode"),
    alphabet: z
      .string()
      .length(64)
      .optional()
      .describe(
        "Custom 64-character alphabet in index order; omitted accepts standard and URL-safe base64",
      ),
  }),
  z.strictObject({ op: z.literal("base32_decode") }),
  z.strictObject({ op: z.literal("hex_decode") }),
  z.strictObject({
    op: z.literal("xor"),
    key_hex: nonEmptyHexBytes.describe("Repeating XOR key"),
  }),
  z.strictObject({
    op: z.literal("rc4"),
    key_hex: nonEmptyHexBytes.describe("RC4 key, 1 to 256 bytes"),
    drop: uint
      .max(65536)
      .default(0)
      .describe("Keystream bytes to discard first (RC4-drop[n])"),
  }),
  z.strictObject({
    op: z.literal("aes_decrypt"),
    mode: z.enum(["ecb", "cbc", "ctr"]),
    key_hex: nonEmptyHexBytes.describe("AES-128, AES-192 or AES-256 key"),
    iv_hex: hexBytes
      .optional()
      .describe("16-byte IV for CBC or initial counter block for CTR"),
    padding: z
      .enum(["pkcs7", "none"])
      .default("pkcs7")
      .describe("Block padding to remove after ECB/CBC decryption"),
  }),
  z.strictObject({
    op: z.literal("inflate"),
    format: z.enum(["zlib", "raw", "gzip"]),
  }),
  z.strictObject({ op: z.literal("reverse") }),
  z.strictObject({ op: z.literal("not") }),
  z.strictObject({
    op: z.literal("add"),
    value: z
      .number()
      .int()
      .min(-255)
      .max(255)
      .describe("Added to every byte modulo 256; negative subtracts"),
  }),
  z.strictObject({
    op: z.literal("rotate_bits"),
    direction: z.enum(["left", "right"]),
    bits: z.number().int().min(1).max(7),
  }),
  z.strictObject({
    op: z.literal("slice"),
    offset: uint,
    length: uint.optional(),
  }),
]);

export const decodeBytesInputSchema = z.strictObject({
  input: decodeInputSchema,
  steps: z.array(decodeStepSchema).min(1).max(32),
  max_bytes: z
    .number()
    .int()
    .min(1)
    .max(268435456)
    .default(16777216)
    .describe(
      "Largest input or step output allowed, in bytes (default 16 MiB); bounds decompression",
    ),
  preview_bytes: z
    .number()
    .int()
    .min(0)
    .max(1048576)
    .default(4096)
    .describe("Bytes of the final output returned inline as hex and text"),
});

const stepFactsSchema = z.strictObject({
  bytes: uint,
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  entropy: z.number().min(0).max(8),
  printable_ratio: z.number().min(0).max(1),
  magic: z.string().nullable(),
});

export const decodeBytesResultSchema = z.strictObject({
  input: stepFactsSchema.extend({
    source: z.enum(["hex", "base64", "text", "file"]),
    file: z
      .strictObject({
        path: z.string().min(1),
        sha256: z.string().regex(/^[a-f0-9]{64}$/),
        bytes: uint,
        offset: uint,
      })
      .nullable(),
  }),
  steps: z.array(
    z
      .strictObject({ index: uint, op: z.string().min(1) })
      .extend(stepFactsSchema.shape),
  ),
  status: z.enum(["complete", "failed"]),
  failure: z
    .strictObject({ step: uint, op: z.string().min(1), reason: z.string() })
    .nullable(),
  output: stepFactsSchema.extend({
    preview_hex: z.string(),
    preview_text: z.string(),
    preview_truncated: z.boolean(),
  }),
  analyst_directed_text: z.array(analystDirectedTextFindingSchema),
  limitations: z.array(z.string()),
});

export type DecodeBytesInput = z.infer<typeof decodeBytesInputSchema>;
export type DecodeStep = z.infer<typeof decodeStepSchema>;
export type DecodeBytesResult = z.infer<typeof decodeBytesResultSchema>;

/** Integer conversion: one value in any common base, or bytes in a stated order. */
export const convertNumberInputSchema = z
  .strictObject({
    value: z
      .string()
      .regex(
        /^(?:\+|-)?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|[0-9_]+)$/,
        "Expected a decimal, 0x hexadecimal, 0b binary or 0o octal integer",
      )
      .optional()
      .describe("Integer such as 0xdeadbeef, -42, 0b1010 or 0o755"),
    bytes_hex: hexBytes
      .optional()
      .describe("1, 2, 4 or 8 bytes to read as an integer"),
    byte_order: z
      .enum(["little", "big"])
      .optional()
      .describe("Byte order of bytes_hex; required with bytes_hex"),
    width: z
      .union([z.literal(8), z.literal(16), z.literal(32), z.literal(64)])
      .optional()
      .describe("Bit width; omitted uses the smallest width that holds value"),
  })
  .refine(
    (input) => (input.value === undefined) !== (input.bytes_hex === undefined),
    {
      message: "Provide exactly one of value or bytes_hex",
    },
  )
  .refine(
    (input) => input.bytes_hex === undefined || input.byte_order !== undefined,
    {
      message: "byte_order is required with bytes_hex",
      path: ["byte_order"],
    },
  );

export const convertNumberResultSchema = z.strictObject({
  width: z.union([z.literal(8), z.literal(16), z.literal(32), z.literal(64)]),
  unsigned: z.string(),
  signed: z.string(),
  hex: z.string(),
  octal: z.string(),
  binary: z.string(),
  bytes_little_endian: z.string(),
  bytes_big_endian: z.string(),
  ascii_little_endian: z.string().nullable(),
  ascii_big_endian: z.string().nullable(),
  float: z.number().nullable(),
  float_note: z.string().nullable(),
});

export type ConvertNumberInput = z.infer<typeof convertNumberInputSchema>;
export type ConvertNumberResult = z.infer<typeof convertNumberResultSchema>;
