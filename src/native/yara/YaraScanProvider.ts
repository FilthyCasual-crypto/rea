import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { basename, extname } from "node:path";
import { pathToFileURL } from "node:url";

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
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  ScanWithYaraInput,
  YaraScan,
} from "../../domain/native/yaraScan.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  detectTriageFormat,
  measureSections,
  parseTriageSections,
} from "../triage/binaryTriageAnalysis.js";

const OPERATION = "scan_with_yara";
const MAX_RULE_FILE_BYTES = 16777216;
const MAX_WARNINGS = 64;
const ENGINE = "YARA-X 1.21.0 (WebAssembly)";

type YaraModule = typeof import("@virustotal/yara-x");

interface RawScanResult {
  readonly valid?: boolean;
  readonly errors?: readonly string[];
  readonly warnings?: readonly string[];
  readonly matches?: readonly {
    readonly identifier: string;
    readonly namespace: string;
    readonly tags: readonly string[];
    readonly metadata: readonly { identifier: string; value: unknown }[];
    readonly patterns: readonly {
      readonly identifier: string;
      readonly kind: string;
      readonly matches: readonly { offset: number; length: number }[];
    }[];
  }[];
}

// The engine is loaded once, on the first scan, so server startup never pays
// for compiling the WebAssembly module.
let engine: Promise<YaraModule> | undefined;
const loadEngine = (): Promise<YaraModule> => {
  engine ??= (async () => {
    const url = pathToFileURL(
      createRequire(import.meta.url).resolve("@virustotal/yara-x"),
    );
    const module = (await import(url.href)) as YaraModule;
    module.initSync({
      module: await readFile(new URL("yara_x_js_bg.wasm", url)),
    });
    return module;
  })();
  return engine;
};

const sha256Of = (bytes: Uint8Array | string) =>
  createHash("sha256").update(bytes).digest("hex");

const metadataValue = (value: unknown): string | number | boolean =>
  typeof value === "string" ||
  typeof value === "boolean" ||
  (typeof value === "number" && Number.isFinite(value))
    ? value
    : String(value);

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

    const yara = await loadEngine();
    const compiler = new yara.Compiler();
    for (const [index, rules] of ruleTexts.entries()) {
      try {
        if (rules.namespace !== null) compiler.newNamespace(rules.namespace);
        compiler.addSource(rules.text);
      } catch (cause) {
        return err(
          new AnalysisInputError(OPERATION, { cause }, [
            {
              path:
                input.rules.kind === "inline"
                  ? ["rules", "source"]
                  : ["rules", "paths", index],
              reason: "invalid_value",
              message: `YARA rules in ${rules.label} did not compile: ${String(cause).slice(0, 2000)}`,
            },
          ]),
        );
      }
    }
    const scanner = compiler.build().scanner();
    scanner.setTimeoutMs(input.timeout_ms);
    scanner.setMaxMatchesPerPattern(input.max_matches_per_pattern);
    let raw: RawScanResult;
    try {
      raw = scanner.scan(target.bytes) as RawScanResult;
    } catch (cause) {
      const message = String(cause);
      return err(
        /timeout|timed out/i.test(message)
          ? new AnalysisResourceConstraintError(
              OPERATION,
              "cpu",
              `YARA scan exceeded timeout_ms (${input.timeout_ms}).`,
              { timeout_ms: input.timeout_ms },
              { cause },
            )
          : new ArtifactOperationError(
              OPERATION,
              "io",
              undefined,
              `YARA scan failed: ${message}`,
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
    let truncated = false;
    const matches: YaraScan["matches"] = (raw.matches ?? []).map((rule) => ({
      rule: rule.identifier,
      namespace: rule.namespace,
      tags: [...rule.tags],
      metadata: rule.metadata.map(({ identifier, value }) => ({
        identifier,
        value: metadataValue(value),
      })),
      patterns: rule.patterns.map((pattern) => {
        const kept = pattern.matches.slice(0, Math.max(0, remaining));
        if (kept.length < pattern.matches.length) truncated = true;
        remaining -= kept.length;
        if (pattern.matches.length >= input.max_matches_per_pattern)
          truncated = true;
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
    const warnings = [...(raw.warnings ?? [])];
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
      scan_errors: [...(raw.errors ?? [])],
      limitations: [
        "Rules are supplied by the caller; a match means the rule's conditions hold for these bytes, not that the rule's name, tags or metadata are correct.",
        "No match means only that these rules did not match; it does not establish that the file is clean.",
        "Rule files are compiled as given; include directives are not resolved.",
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
