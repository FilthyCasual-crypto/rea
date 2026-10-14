import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { ByteDecodingService } from "../application/binaryDiagnostics/ByteDecodingService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Register deterministic byte decoding and number conversion with retained Evidence. */
export const registerByteDecodingTools = (
  server: EvidenceMcpServer,
  service: ByteDecodingService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const decode = toolContract("decode_bytes");
  server.registerTool(
    decode.name,
    toolRegistrationOptions(decode),
    createEvidenceToolHandler(
      server,
      (input, options) => service.decode(input, options),
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    )(decode),
  );
  const convert = toolContract("convert_number");
  server.registerTool(
    convert.name,
    toolRegistrationOptions(convert),
    createEvidenceToolHandler(
      server,
      (input) => Promise.resolve(service.convert(input)),
      logger,
      recordEvidence,
      withAdmittedAnalysis,
    )(convert),
  );
};
