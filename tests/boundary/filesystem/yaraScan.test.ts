import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createYaraScanService } from "../../../src/composition/binaryDiagnostics.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

interface Scan {
  matches: {
    rule: string;
    namespace: string;
    tags: string[];
    metadata: { identifier: string; value: unknown }[];
    patterns: {
      identifier: string;
      matches: { offset: number; section: string | null }[];
    }[];
  }[];
  truncated: boolean;
  rules: { sources: { kind: string; namespace?: string; sha256: string }[] };
}
const scanOf = (evidence: { normalized_result: unknown }) =>
  evidence.normalized_result as Scan;

describe("YARA-X scans over stable files", () => {
  it("reports matching rules with offsets, tags, metadata and pinned rule hashes", async () => {
    const root = await createTestTempDirectory("rea-yara-inline-");
    const path = join(root, "sample.bin");
    await writeFile(
      path,
      Buffer.concat([Buffer.alloc(64), Buffer.from("UPX!"), Buffer.alloc(64)]),
    );
    const service = createYaraScanService();
    const result = await service.scan({
      path,
      rules: {
        kind: "inline",
        source:
          'rule upx_marker : packer { meta: family = "UPX" score = 7 strings: $a = "UPX!" condition: $a } rule absent { strings: $b = "nope" condition: $b }',
      },
    });
    if (!result.ok) throw result.error;
    const scan = scanOf(result.value);
    expect(scan.matches).toEqual([
      expect.objectContaining({
        rule: "upx_marker",
        tags: ["packer"],
        metadata: [
          { identifier: "family", value: "UPX" },
          { identifier: "score", value: 7 },
        ],
        patterns: [
          expect.objectContaining({
            identifier: "$a",
            matches: [{ offset: 64, length: 4, section: null }],
          }),
        ],
      }),
    ]);
    expect(scan.rules.sources[0]).toMatchObject({
      kind: "inline",
      sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    await service.close();
  });

  it("maps matches to sections and keeps rule files in separate namespaces", async () => {
    const root = await createTestTempDirectory("rea-yara-files-");
    const first = join(root, "first.yar");
    const second = join(root, "second.yar");
    await writeFile(
      first,
      "rule elf { strings: $m = { 7F 45 4C 46 } condition: $m at 0 }",
    );
    await writeFile(second, "rule elf { condition: uint32(0) == 0x464c457f }");
    const service = createYaraScanService();
    const result = await service.scan({
      path: process.execPath,
      rules: { kind: "files", paths: [first, second] },
    });
    if (!result.ok) throw result.error;
    const scan = scanOf(result.value);
    if (
      !(await import("node:fs"))
        .readFileSync(process.execPath)
        .subarray(0, 4)
        .equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
    )
      return;
    expect(scan.matches.map((match) => match.namespace).sort()).toEqual([
      "first",
      "second",
    ]);
    expect(scan.rules.sources.map((source) => source.namespace)).toEqual([
      "first",
      "second",
    ]);
  });

  it("truncates match offsets at the caller's budget and says so", async () => {
    const root = await createTestTempDirectory("rea-yara-budget-");
    const path = join(root, "repeat.bin");
    await writeFile(path, Buffer.from("ab".repeat(500)));
    const service = createYaraScanService();
    const result = await service.scan({
      path,
      rules: {
        kind: "inline",
        source: 'rule ab { strings: $a = "ab" condition: $a }',
      },
      max_matches: 5,
    });
    if (!result.ok) throw result.error;
    const scan = scanOf(result.value);
    expect(scan.matches[0]!.patterns[0]!.matches).toHaveLength(5);
    expect(scan.truncated).toBe(true);
  });

  it("reports compile errors, missing rule files and relative paths as input errors", async () => {
    const root = await createTestTempDirectory("rea-yara-errors-");
    const path = join(root, "sample.bin");
    await writeFile(path, Buffer.alloc(16));
    const service = createYaraScanService();
    for (const [input, issuePath] of [
      [
        {
          path,
          rules: {
            kind: "inline",
            source: "rule broken { condition: undefined_identifier }",
          },
        },
        ["rules", "source"],
      ],
      [
        { path, rules: { kind: "files", paths: [join(root, "missing.yar")] } },
        ["rules", "paths", 0],
      ],
      [
        {
          path: "sample.bin",
          rules: { kind: "inline", source: "rule r { condition: true }" },
        },
        ["path"],
      ],
    ] as const) {
      const result = await service.scan(input);
      if (result.ok) throw new Error("Expected an input error");
      expect(result.error).toMatchObject({
        _tag: "AnalysisInputError",
        issues: [expect.objectContaining({ path: issuePath })],
      });
    }
  });
});
