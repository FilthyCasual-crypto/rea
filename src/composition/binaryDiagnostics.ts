import { RecordedCrashService } from "../application/binaryDiagnostics/RecordedCrashService.js";
import { PwntoolsRecordedCrashProvider } from "../native/pwntools/PwntoolsRecordedCrashProvider.js";
import { BinaryLayoutService } from "../application/binaryDiagnostics/BinaryLayoutService.js";
import { PwntoolsLayoutProvider } from "../native/pwntools/PwntoolsLayoutProvider.js";
import { PeResourcesService } from "../application/binaryDiagnostics/PeResourcesService.js";
import { BinaryTriageService } from "../application/binaryDiagnostics/BinaryTriageService.js";
import { BinaryTriageProvider } from "../native/triage/BinaryTriageProvider.js";
import { PeResourcesProvider } from "../native/pe/PeResourcesProvider.js";
import { ByteDecodingService } from "../application/binaryDiagnostics/ByteDecodingService.js";
import { ByteDecodingProvider } from "../native/decode/ByteDecodingProvider.js";
import { YaraScanService } from "../application/binaryDiagnostics/YaraScanService.js";
import { YaraScanProvider } from "../native/yara/YaraScanProvider.js";

/** Portable PE inspection with no engine, installation or target acquisition. */
export const createPeResourcesService = (): PeResourcesService =>
  new PeResourcesService(new PeResourcesProvider());

/** Compose the offline adapter without import-time I/O or dependency acquisition. */
export const createBinaryLayoutService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): BinaryLayoutService =>
  new BinaryLayoutService(new PwntoolsLayoutProvider(environment));

/** Compose recorded-core inspection without acquiring a debugger or toolchain. */
export const createRecordedCrashService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): RecordedCrashService =>
  new RecordedCrashService(new PwntoolsRecordedCrashProvider(environment));

/** Portable byte-level triage with no engine, installation or execution. */
export const createBinaryTriageService = (): BinaryTriageService =>
  new BinaryTriageService(new BinaryTriageProvider());

/** Deterministic byte decoding and number conversion with no installation. */
export const createByteDecodingService = (): ByteDecodingService =>
  new ByteDecodingService(new ByteDecodingProvider());

/** Caller-supplied YARA rules in the bundled WebAssembly engine. */
export const createYaraScanService = (): YaraScanService =>
  new YaraScanService(new YaraScanProvider());
