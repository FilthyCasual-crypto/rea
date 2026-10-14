import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  ConvertNumberInput,
  ConvertNumberResult,
  DecodeBytesInput,
  DecodeBytesResult,
} from "../../domain/native/byteDecoding.js";
import type { Result } from "../../domain/result.js";

/** Deterministic byte transforms and integer conversion, without execution. */
export interface ByteDecodingPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  decode(
    input: DecodeBytesInput,
    options?: ExecutionOptions,
  ): Promise<Result<DecodeBytesResult, AnalysisError>>;
  convert(
    input: ConvertNumberInput,
  ): Result<ConvertNumberResult, AnalysisError>;
}
