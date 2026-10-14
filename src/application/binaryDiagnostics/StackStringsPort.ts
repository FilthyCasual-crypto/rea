import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  ExtractStackStringsInput,
  StackStrings,
} from "../../domain/native/stackStrings.js";
import type { Result } from "../../domain/result.js";

/** Stack-built string recovery over one stable file, without execution. */
export interface StackStringsPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  extract(
    input: ExtractStackStringsInput,
    options?: ExecutionOptions,
  ): Promise<Result<StackStrings, AnalysisError>>;
}
