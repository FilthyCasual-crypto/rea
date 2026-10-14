import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { analysisErrorWithCleanupFailure } from "../../domain/analysisErrorCleanup.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { ArtifactOperationError } from "../../domain/artifactOperationError.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";

type Operation = ConstructorParameters<typeof ArtifactOperationError>[0];

/** Map a failed stable read of one caller-selected file to a typed analysis error. */
export const stableFileFailure = (
  operation: Operation,
  providerId: string,
  cause: unknown,
  path: string,
  limits: Readonly<Record<string, JsonValue>>,
  signal: AbortSignal | undefined,
): AnalysisError => {
  const primary = primaryFailure(operation, cause, path, limits, signal);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    providerId,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { operation, cause },
  );
  return analysisErrorWithCleanupFailure(primary, cleanup, operation);
};

const primaryFailure = (
  operation: Operation,
  cause: unknown,
  path: string,
  limits: Readonly<Record<string, JsonValue>>,
  signal: AbortSignal | undefined,
): AnalysisError => {
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(operation, path, cause.message, {
      cause,
    });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(operation, { cause });
  if (signal?.aborted) return new AnalysisCancelledError(operation, { cause });
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        operation,
        "memory",
        cause.message,
        limits,
        { cause },
      );
    if (cause.reason === "path" || cause.reason === "format")
      return new AnalysisInputError(operation, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(operation, path, cause.code, {
        cause,
      });
    if (cause.code === "ENOENT" || cause.code === "ENOTDIR")
      return new AnalysisInputError(operation, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected file could not be read (${cause.code}): ${path}.`,
        },
      ]);
  }
  return new ArtifactOperationError(
    operation,
    cause instanceof ArtifactReaderFailure ? cause.reason : "io",
    undefined,
    cause instanceof Error
      ? cause.message
      : "Reading the selected file failed.",
    { cause },
  );
};
