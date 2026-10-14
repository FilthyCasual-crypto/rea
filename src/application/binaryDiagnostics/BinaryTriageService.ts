import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { BinaryTriagePort } from "./BinaryTriagePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  binaryTriageSchema,
  inspectBinaryTriageInputSchema,
  type BinaryTriage,
  type TriageFormat,
} from "../../domain/native/binaryTriage.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_binary_triage";

const SUBJECT_FORMAT = {
  elf: "elf",
  pe: "pe",
  "dos-mz": "dos-mz",
  "mach-o": "mach-o",
  "mach-o-universal": "mach-o-universal",
  zip: "zip",
  dex: "file",
  wasm: "file",
  "java-class": "file",
  unknown: "file",
} as const satisfies Record<TriageFormat, string>;

/** Shared caller validation, output checks and Evidence provenance for CLI/MCP. */
export class BinaryTriageService {
  constructor(readonly provider: BinaryTriagePort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectBinaryTriageInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const result = await this.provider.inspect(input.data, options);
    if (!result.ok) return result;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const report = binaryTriageSchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      !validReport(
        report.data,
        input.data.max_file_bytes,
        input.data.max_findings,
      )
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Binary triage provider returned malformed output or changed artifact identity.",
        ),
      );
    const value = report.data;
    return ok(
      createEvidence(
        {
          path: value.artifact.path,
          format: SUBJECT_FORMAT[value.format],
          sha256: value.artifact.sha256,
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.data,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
    );
  }
}

/** Every reported range must lie inside the artifact the provider read. */
const validReport = (
  report: BinaryTriage,
  maxBytes: number,
  maxFindings: number,
): boolean => {
  const inside = ({ offset, bytes }: { offset: number; bytes: number }) =>
    offset + bytes <= report.artifact.bytes;
  return (
    report.artifact.bytes <= maxBytes &&
    report.analyst_directed_text.findings.length <= maxFindings &&
    report.sections.every((section) => inside(section.location)) &&
    report.packer_indicators.every(
      (indicator) => indicator.location === null || inside(indicator.location),
    ) &&
    report.analyst_directed_text.findings.every((finding) =>
      inside(finding.location),
    ) &&
    (report.section_coverage === "complete" || report.sections.length === 0)
  );
};
