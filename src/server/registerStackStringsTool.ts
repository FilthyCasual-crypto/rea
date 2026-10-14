import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { StackStringsService } from "../application/binaryDiagnostics/StackStringsService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Register stack-built string recovery and retain its complete Evidence. */
export const registerStackStringsTool = (
  server: EvidenceMcpServer,
  service: StackStringsService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("extract_stack_strings");
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.extract(input, options),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    handler(contract),
  );
};
