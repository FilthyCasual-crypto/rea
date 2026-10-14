import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { ByteDecodingPort } from "./ByteDecodingPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  convertNumberInputSchema,
  convertNumberResultSchema,
  decodeBytesInputSchema,
  decodeBytesResultSchema,
} from "../../domain/native/byteDecoding.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";

const DECODE = "decode_bytes";
const CONVERT = "convert_number";

// Parsed inputs keep omitted optional fields as undefined; Evidence parameters
// record exactly the JSON the caller's choices serialize to.
const jsonParameters = (value: object) =>
  jsonObjectSchema.parse(JSON.parse(JSON.stringify(value)));

/** Shared validation and Evidence provenance for deterministic byte work. */
export class ByteDecodingService {
  constructor(readonly provider: ByteDecodingPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async decode(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(DECODE));
    const input = decodeBytesInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(DECODE, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const source = input.data.input;
    if (source.kind === "file" && !isAbsolute(source.path))
      return err(
        new AnalysisInputError(DECODE, undefined, [
          {
            path: ["input", "path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const result = await this.provider.decode(input.data, options);
    if (!result.ok) return result;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(DECODE));
    const report = decodeBytesResultSchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.steps.length > input.data.steps.length ||
      (report.data.status === "complete") !== (report.data.failure === null) ||
      (source.kind === "file") !== (report.data.input.file !== null)
    )
      return err(
        new AnalysisOutputError(
          DECODE,
          "Byte decoding returned malformed output.",
        ),
      );
    const value = report.data;
    const file = value.input.file;
    return ok(
      createEvidence(
        file === null
          ? undefined
          : { path: file.path, format: "file", sha256: file.sha256 },
        this.provider.identity,
        {
          operation: DECODE,
          parameters: jsonParameters(input.data),
          result: value,
          confidence: "derived",
          limitations: value.limitations,
          locations:
            file === null ? [] : [{ kind: "artifact-path", path: file.path }],
        },
      ),
    );
  }

  convert(rawInput: unknown): Result<Evidence, AnalysisError> {
    const input = convertNumberInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(CONVERT, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const result = this.provider.convert(input.data);
    if (!result.ok) return result;
    const report = convertNumberResultSchema.safeParse(result.value);
    if (!report.success)
      return err(
        new AnalysisOutputError(
          CONVERT,
          "Number conversion returned malformed output.",
        ),
      );
    return ok(
      createEvidence(undefined, this.provider.identity, {
        operation: CONVERT,
        parameters: jsonParameters(input.data),
        result: report.data,
        confidence: "derived",
        limitations: [],
        locations: [],
      }),
    );
  }
}
