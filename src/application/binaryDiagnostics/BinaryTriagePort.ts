import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  BinaryTriage,
  InspectBinaryTriageInput,
} from "../../domain/native/binaryTriage.js";
import type { Result } from "../../domain/result.js";

/** Stable read and byte-level triage, independent of any disassembler session. */
export interface BinaryTriagePort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectBinaryTriageInput,
    options?: ExecutionOptions,
  ): Promise<Result<BinaryTriage, AnalysisError>>;
}
