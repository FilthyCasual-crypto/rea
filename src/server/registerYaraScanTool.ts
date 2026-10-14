import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { YaraScanService } from "../application/binaryDiagnostics/YaraScanService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Register caller-supplied YARA scans and retain its complete Evidence. */
export const registerYaraScanTool = (
  server: EvidenceMcpServer,
  service: YaraScanService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("scan_with_yara");
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.scan(input, options),
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
