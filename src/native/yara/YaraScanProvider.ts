import { createHash } from "node:crypto";
import { basename, extname } from "node:path";

import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import { YARA_SCAN_PROVIDER } from "../../application/InvestigationProviders.js";
import type { YaraScanPort } from "../../application/binaryDiagnostics/YaraScanPort.js";
import { ArtifactOperationError } from "../../domain/artifactOperationError.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  ScanWithYaraInput,
  YaraScan,
} from "../../domain/native/yaraScan.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  compileRules,
  RuleCompileError,
  RuleScanTimeout,
  scanWithRules,
  type CompiledRules,
} from "../rules/ruleEngine.js";
import {
  detectTriageFormat,
  measureSections,
  parseTriageSections,
} from "../triage/binaryTriageAnalysis.js";

const OPERATION = "scan_with_yara";
const MAX_RULE_FILE_BYTES = 16777216;
const MAX_WARNINGS = 64;
const ENGINE = "Ghostwire rule engine 1 (YARA rule syntax subset)";

const sha256Of = (bytes: Uint8Array | string) =>
  createHash("sha256").update(bytes).digest("hex");

const namespaceFor = (path: string, used: Set<string>): string => {
  const stem =
    basename(path, extname(path)).replace(/[^A-Za-z0-9_]/g, "_") || "rules";
  let candidate = /^[A-Za-z_]/.test(stem) ? stem : `rules_${stem}`;
  for (let index = 2; used.has(candidate); index++)
    candidate = `${stem}_${index}`;
  used.add(candidate);
  return candidate;
};

/** Scan one stable file with caller-supplied YARA rules in the bundled engine. */
export class YaraScanProvider implements YaraScanPort {
  readonly identity = YARA_SCAN_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  close(): Promise<void> {
    return this.#resources.close();
  }

  async scan(
    input: ScanWithYaraInput,
    options?: ExecutionOptions,
  ): Promise<Result<YaraScan, AnalysisError>> {
    const signal = options?.signal;
    const sources: YaraScan["rules"]["sources"] = [];
    const ruleTexts: {
      namespace: string | null;
      text: string;
      label: string;
    }[] = [];
    if (input.rules.kind === "inline") {
      sources.push({
        kind: "inline",
        sha256: sha256Of(input.rules.source),
        bytes: Buffer.byteLength(input.rules.source),
      });
      ruleTexts.push({
        namespace: null,
        text: input.rules.source,
        label: "inline rules",
      });
    } else {
      const used = new Set<string>();
      for (const [index, path] of input.rules.paths.entries()) {
        let snapshot;
        try {
          snapshot = await this.#resources.run(() =>
            readStableArtifact(
              path,
              MAX_RULE_FILE_BYTES,
              signal,
              undefined,
              this.#resources,
            ),
          );
        } catch (cause) {
          return err(
            readFailure(cause, path, ["rules", "paths", index], signal),
          );
        }
        const namespace = namespaceFor(path, used);
        sources.push({
          kind: "file",
          path,
          namespace,
          sha256: snapshot.sha256,
          bytes: snapshot.bytes.length,
        });
        ruleTexts.push({
          namespace,
          text: snapshot.bytes.toString("utf8"),
          label: path,
        });
      }
    }
    let target;
    try {
      target = await this.#resources.run(() =>
        readStableArtifact(
          input.path,
          input.max_file_bytes,
          signal,
          undefined,
          this.#resources,
        ),
      );
    } catch (cause) {
      return err(readFailure(cause, input.path, ["path"], signal));
    }
    if (signal?.aborted) return err(new AnalysisCancelledError(OPERATION));

    let compiled: CompiledRules;
    try {
      compiled = compileRules(
        ruleTexts.map((rules) => ({
          namespace: rules.namespace ?? "default",
          text: rules.text,
          label: rules.label,
        })),
      );
    } catch (cause) {
      if (!(cause instanceof RuleCompileError)) throw cause;
      const index = Math.max(
        0,
        ruleTexts.findIndex(({ label }) =>
          cause.message.startsWith(`${label}:`),
        ),
      );
      return err(
        new AnalysisInputError(OPERATION, { cause }, [
          {
            path:
              input.rules.kind === "inline"
                ? ["rules", "source"]
                : ["rules", "paths", index],
            reason: "invalid_value",
            message: `Rules did not compile: ${cause.message.slice(0, 2000)}`,
          },
        ]),
      );
    }
    let scanned: ReturnType<typeof scanWithRules>;
    try {
      scanned = scanWithRules(compiled, target.bytes, {
        maxMatchesPerPattern: input.max_matches_per_pattern,
        deadline: Date.now() + input.timeout_ms,
      });
    } catch (cause) {
      if (cause instanceof RuleScanTimeout)
        return err(
          new AnalysisTimeoutError(OPERATION, input.timeout_ms, { cause }),
        );
      return err(
        new ArtifactOperationError(
          OPERATION,
          "io",
          undefined,
          `Rule scan failed: ${cause instanceof Error ? cause.message : String(cause)}`,
          { cause },
        ),
      );
    }

    const format = detectTriageFormat(target.bytes);
    const { sections } = measureSections(
      target.bytes,
      parseTriageSections(target.bytes, format),
    );
    const sectionAt = (offset: number) =>
      sections.find(
        ({ location }) =>
          offset >= location.offset &&
          offset < location.offset + location.bytes,
      )?.name ?? null;

    let remaining = input.max_matches;
    let truncated = scanned.truncated;
    const matches: YaraScan["matches"] = scanned.matches.map((rule) => ({
      rule: rule.rule,
      namespace: rule.namespace,
      tags: [...rule.tags],
      metadata: rule.metadata.map((entry) => ({ ...entry })),
      patterns: rule.patterns.map((pattern) => {
        const kept = pattern.matches.slice(0, Math.max(0, remaining));
        if (kept.length < pattern.matches.length) truncated = true;
        remaining -= kept.length;
        return {
          identifier: pattern.identifier,
          kind: pattern.kind,
          matches: kept.map(({ offset, length }) => ({
            offset,
            length,
            section: sectionAt(offset),
          })),
        };
      }),
    }));
    const warnings: string[] = [];
    return ok({
      artifact: {
        path: input.path,
        sha256: target.sha256,
        bytes: target.bytes.length,
      },
      rules: {
        sources,
        warnings: warnings.slice(0, MAX_WARNINGS),
        engine: ENGINE,
      },
      matches,
      matched_rules: matches.length,
      truncated,
      scan_errors: [],
      limitations: [
        "Rules are supplied by the caller; a match means the rule's conditions hold for these bytes, not that the rule's name, tags or metadata are correct.",
        "No match means only that these rules did not match; it does not establish that the file is clean.",
        "Rules run in Ghostwire's own engine, which implements a subset of the YARA rule language: modules (pe, elf, math, hash), for loops, base64 modifiers, percentage quantifiers and include directives fail compilation with a message naming the feature.",
        "Regular-expression strings use JavaScript regular-expression semantics over the file's bytes, which differ from YARA's in some edge cases.",
        ...(warnings.length > MAX_WARNINGS
          ? [
              `${warnings.length - MAX_WARNINGS} further compiler warnings were omitted.`,
            ]
          : []),
        ...(truncated
          ? [
              "Match offsets were truncated by max_matches or max_matches_per_pattern; matched rules are still complete.",
            ]
          : []),
      ],
    });
  }
}

const readFailure = (
  cause: unknown,
  path: string,
  inputPath: (string | number)[],
  signal: AbortSignal | undefined,
): AnalysisError => {
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, cause.message, {
      cause,
    });
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    signal?.aborted
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "limit")
    return new AnalysisResourceConstraintError(
      OPERATION,
      "memory",
      cause.message,
      {},
      { cause },
    );
  if (
    cause instanceof ArtifactReaderFailure &&
    (cause.reason === "path" || cause.reason === "format")
  )
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: inputPath, reason: "invalid_format", message: cause.message },
    ]);
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
        cause,
      });
    if (cause.code === "ENOENT" || cause.code === "ENOTDIR")
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: inputPath,
          reason: "invalid_value",
          message: `Selected file could not be read (${cause.code}): ${path}.`,
        },
      ]);
  }
  return new ArtifactOperationError(
    OPERATION,
    cause instanceof ArtifactReaderFailure ? cause.reason : "io",
    undefined,
    cause instanceof Error ? cause.message : "Reading a YARA input failed.",
    { cause },
  );
};
