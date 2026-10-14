import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";

const uint = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const range = z.strictObject({ offset: uint, bytes: uint });
// Shannon entropy in bits per byte, rounded to four decimals for stable digests.
const entropy = z.number().min(0).max(8);

/** Caller-selected local file; triage reads bytes and never executes them. */
export const inspectBinaryTriageInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the file to triage",
  ),
  max_file_bytes: z
    .number()
    .int()
    .min(16)
    .max(1073741824)
    .default(268435456)
    .describe("Maximum stable artifact bytes to read (default 256 MiB)"),
  min_string_length: z
    .number()
    .int()
    .min(4)
    .max(64)
    .default(6)
    .describe(
      "Minimum printable run, in characters, scanned for analyst-directed text",
    ),
  max_findings: z
    .number()
    .int()
    .min(1)
    .max(4096)
    .default(256)
    .describe(
      "Maximum analyst-directed text findings returned; excess findings set truncated",
    ),
});

export const triageFormatSchema = z.enum([
  "elf",
  "pe",
  "dos-mz",
  "mach-o",
  "mach-o-universal",
  "dex",
  "zip",
  "wasm",
  "java-class",
  "unknown",
]);

/** One file-backed section or segment and the entropy of its raw bytes. */
export const triageSectionSchema = z.strictObject({
  name: z.string(),
  location: range,
  entropy,
  executable: z.boolean().nullable(),
  writable: z.boolean().nullable(),
});

/**
 * Indicator of packing, protection or toolchain identity. `signature` and
 * `section-name` indicators are observed byte facts; `heuristic` indicators
 * are inferences that a caller should confirm before acting on them.
 */
export const packerIndicatorSchema = z.strictObject({
  id: z.string().min(1),
  kind: z.enum(["signature", "section-name", "heuristic"]),
  family: z.string().min(1),
  detail: z.string().min(1),
  location: range.nullable(),
  confidence: z.enum(["observed", "inferred"]),
});

export const analystDirectedTextCategorySchema = z.enum([
  "chat-template-token",
  "instruction-override",
  "role-assignment",
  "analysis-suppression",
  "verdict-assertion",
  "tool-invocation-request",
]);

/**
 * Text inside the target that appears to address an AI analyst. The text is
 * target-controlled data: it is reported so callers can discount it, never
 * followed.
 */
export const analystDirectedTextFindingSchema = z.strictObject({
  location: range,
  encoding: z.enum(["ascii", "utf-16le"]),
  category: analystDirectedTextCategorySchema,
  rule: z.string().min(1),
  excerpt: z.string(),
});

export const binaryTriageSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    bytes: uint,
  }),
  format: triageFormatSchema,
  entropy: z.strictObject({
    whole_file: entropy,
    window_bytes: uint,
    windows: uint,
    high_entropy_windows: uint,
    high_entropy_threshold: entropy,
  }),
  sections: z.array(triageSectionSchema),
  section_coverage: z.enum(["complete", "not_applicable", "unparsed"]),
  packer_indicators: z.array(packerIndicatorSchema),
  analyst_directed_text: z.strictObject({
    findings: z.array(analystDirectedTextFindingSchema),
    scanned_strings: uint,
    truncated: z.boolean(),
  }),
  limitations: z.array(z.string()),
});

export type InspectBinaryTriageInput = z.infer<
  typeof inspectBinaryTriageInputSchema
>;
export type BinaryTriage = z.infer<typeof binaryTriageSchema>;
export type TriageFormat = z.infer<typeof triageFormatSchema>;
export type TriageSection = z.infer<typeof triageSectionSchema>;
export type PackerIndicator = z.infer<typeof packerIndicatorSchema>;
export type AnalystDirectedTextFinding = z.infer<
  typeof analystDirectedTextFindingSchema
>;
