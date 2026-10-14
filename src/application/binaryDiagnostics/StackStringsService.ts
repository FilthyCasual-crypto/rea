import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { StackStringsPort } from "./StackStringsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  extractStackStringsInputSchema,
  stackStringsSchema,
  type StackStrings,
} from "../../domain/native/stackStrings.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "extract_stack_strings";

/** Shared validation and Evidence provenance for stack-string recovery over CLI/MCP. */
export class StackStringsService {
  constructor(readonly provider: StackStringsPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async extract(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = extractStackStringsInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const relative = isAbsolute(input.data.path) ? [] : [["path"]];
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
    const result = await this.provider.extract(input.data, options);
    if (!result.ok) return result;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const report = stackStringsSchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      !inside(report.data)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Stack-string provider returned malformed output or changed artifact identity.",
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
          confidence: "derived",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
    );
  }
}

/** Every recovered string must point at instructions inside the artifact. */
const inside = (report: StackStrings): boolean =>
  report.strings.every(
    (item) =>
      item.first_instruction_offset <= item.last_instruction_offset &&
      item.last_instruction_offset < report.artifact.bytes,
  );
