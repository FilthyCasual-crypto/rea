import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";

const uint = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

/** One explicit x86 or x86-64 executable to scan for stack-built strings. */
export const extractStackStringsInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute path of the executable to scan",
  ),
  min_length: z
    .number()
    .int()
    .min(4)
    .max(64)
    .default(6)
    .describe("Minimum string length in characters"),
  max_file_bytes: z
    .number()
    .int()
    .min(64)
    .max(1073741824)
    .default(268435456)
    .describe("Maximum stable artifact bytes to read (default 256 MiB)"),
  max_strings: z
    .number()
    .int()
    .min(1)
    .max(200000)
    .default(20000)
    .describe("Strings returned; excess strings set truncated"),
});

export const stackStringSchema = z.strictObject({
  string: z.string(),
  encoding: z.enum(["ascii", "utf-16le"]),
  section: z.string(),
  first_instruction_offset: uint.describe(
    "File offset of the first instruction that wrote the string",
  ),
  last_instruction_offset: uint.describe(
    "File offset of the last instruction that wrote the string",
  ),
  base_register: z
    .string()
    .describe("Register the stores address, usually rbp or rsp"),
  frame_offset: z
    .number()
    .int()
    .describe("Displacement of the first character from the base register"),
  stores: uint.describe("Store instructions that contributed bytes"),
});

export const stackStringsSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    bytes: uint,
  }),
  format: z.string(),
  architecture: z.enum(["x86", "x86-64", "arm", "arm64", "other", "unknown"]),
  scanned_regions: z.array(
    z.strictObject({ name: z.string(), offset: uint, bytes: uint }),
  ),
  strings: z.array(stackStringSchema),
  truncated: z.boolean(),
  limitations: z.array(z.string()),
});

export type ExtractStackStringsInput = z.infer<
  typeof extractStackStringsInputSchema
>;
export type StackStrings = z.infer<typeof stackStringsSchema>;
