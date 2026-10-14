import { z } from "zod";

import { localPathStringSchema } from "../localPath.js";

const uint = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);

/** Rules come from the caller, inline or as local rule files; Ghostwire ships none. */
export const yaraRulesInputSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("inline"),
    source: z.string().min(1).max(4194304).describe("YARA rule source text"),
  }),
  z.strictObject({
    kind: z.literal("files"),
    paths: z
      .array(localPathStringSchema)
      .min(1)
      .max(256)
      .describe(
        "Absolute paths of YARA rule files; each file gets its own namespace",
      ),
  }),
]);

export const scanWithYaraInputSchema = z.strictObject({
  path: localPathStringSchema.describe("Absolute path of the file to scan"),
  rules: yaraRulesInputSchema,
  max_file_bytes: z
    .number()
    .int()
    .min(1)
    .max(1073741824)
    .default(268435456)
    .describe("Maximum stable artifact bytes to read (default 256 MiB)"),
  timeout_ms: z
    .number()
    .int()
    .min(100)
    .max(600000)
    .default(60000)
    .describe("Hard scan timeout in milliseconds"),
  max_matches_per_pattern: z
    .number()
    .int()
    .min(1)
    .max(100000)
    .default(64)
    .describe("Match offsets kept per pattern"),
  max_matches: z
    .number()
    .int()
    .min(1)
    .max(100000)
    .default(4096)
    .describe(
      "Match offsets returned across all rules; excess offsets set truncated",
    ),
});

const metadataValue = z.union([z.string(), z.number(), z.boolean()]);

export const yaraScanSchema = z.strictObject({
  artifact: z.strictObject({ path: z.string().min(1), sha256, bytes: uint }),
  rules: z.strictObject({
    sources: z.array(
      z.discriminatedUnion("kind", [
        z.strictObject({ kind: z.literal("inline"), sha256, bytes: uint }),
        z.strictObject({
          kind: z.literal("file"),
          path: z.string().min(1),
          namespace: z.string().min(1),
          sha256,
          bytes: uint,
        }),
      ]),
    ),
    warnings: z.array(z.string()),
    engine: z.string().min(1),
  }),
  matches: z.array(
    z.strictObject({
      rule: z.string().min(1),
      namespace: z.string(),
      tags: z.array(z.string()),
      metadata: z.array(
        z.strictObject({ identifier: z.string(), value: metadataValue }),
      ),
      patterns: z.array(
        z.strictObject({
          identifier: z.string(),
          kind: z.string(),
          matches: z.array(
            z.strictObject({
              offset: uint,
              length: uint,
              section: z.string().nullable(),
            }),
          ),
        }),
      ),
    }),
  ),
  matched_rules: uint,
  truncated: z.boolean(),
  scan_errors: z.array(z.string()),
  limitations: z.array(z.string()),
});

export type ScanWithYaraInput = z.infer<typeof scanWithYaraInputSchema>;
export type YaraScan = z.infer<typeof yaraScanSchema>;
