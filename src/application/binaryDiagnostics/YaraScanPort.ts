import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  ScanWithYaraInput,
  YaraScan,
} from "../../domain/native/yaraScan.js";
import type { Result } from "../../domain/result.js";

/** Caller-supplied YARA rules over one stable file, in a bundled engine. */
export interface YaraScanPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  scan(
    input: ScanWithYaraInput,
    options?: ExecutionOptions,
  ): Promise<Result<YaraScan, AnalysisError>>;
}
