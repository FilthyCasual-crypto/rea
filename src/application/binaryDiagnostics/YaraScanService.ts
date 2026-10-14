import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { YaraScanPort } from "./YaraScanPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  scanWithYaraInputSchema,
  yaraScanSchema,
  type YaraScan,
} from "../../domain/native/yaraScan.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "scan_with_yara";

/** Shared validation and Evidence provenance for YARA scans over CLI/MCP. */
export class YaraScanService {
  constructor(readonly provider: YaraScanPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async scan(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = scanWithYaraInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const relative = [
      ...(isAbsolute(input.data.path) ? [] : [["path"]]),
      ...(input.data.rules.kind === "files"
        ? input.data.rules.paths.flatMap((path, index) =>
            isAbsolute(path) ? [] : [["rules", "paths", index]],
          )
        : []),
    ];
    if (relative.length > 0)
      return err(
        new AnalysisInputError(
          OPERATION,
          undefined,
          relative.map((path) => ({
            path,
            reason: "invalid_format" as const,
            message: "Expected an absolute filesystem path on this host.",
          })),
        ),
      );
    const result = await this.provider.scan(input.data, options);
    if (!result.ok) return result;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const report = yaraScanSchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      !inside(report.data)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "YARA provider returned malformed output or changed artifact identity.",
        ),
      );
    const value = report.data;
    return ok(
      createEvidence(
        {
          path: value.artifact.path,
          format: "file",
          sha256: value.artifact.sha256,
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: jsonObjectSchema.parse(
            JSON.parse(JSON.stringify(input.data)),
          ),
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
    );
  }
}

/** Every reported match must lie inside the scanned artifact. */
const inside = (report: YaraScan): boolean =>
  report.matches.every((rule) =>
    rule.patterns.every((pattern) =>
      pattern.matches.every(
        ({ offset, length }) => offset + length <= report.artifact.bytes,
      ),
    ),
  );
