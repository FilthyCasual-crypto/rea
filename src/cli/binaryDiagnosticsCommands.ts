import { z } from "incur";
import { resolve } from "node:path";
import {
  createRecordedCrashService,
  createBinaryLayoutService,
  createPeResourcesService,
  createBinaryTriageService,
  createByteDecodingService,
  createYaraScanService,
} from "../composition/binaryDiagnostics.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { inspectPeResourcesInputSchema } from "../domain/native/peResources.js";
import { inspectBinaryTriageInputSchema } from "../domain/native/binaryTriage.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { parseCliJsonInput } from "../cliJsonInput.js";
import { convertNumberInputSchema } from "../domain/native/byteDecoding.js";
import { scanWithYaraInputSchema } from "../domain/native/yaraScan.js";

/** Inspect operator-selected files through the same shared workflow as MCP. */
export const registerBinaryDiagnosticsCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<NodeJS.ProcessEnv>,
): void => {
  cli.command(CLI_COMMANDS.inspectPeResources, {
    description:
      "Inspect PE resource identities, payload ranges, hashes and icon-group relationships",
    args: z.object({ path: z.string().describe("Local PE32/PE32+ image") }),
    options: z.object({
      maxFileBytes: inspectPeResourcesInputSchema.shape.max_file_bytes,
      maxEntries: inspectPeResourcesInputSchema.shape.max_entries,
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        const pe = createPeResourcesService();
        return await logCliCommand(
          logger,
          CLI_COMMANDS.inspectPeResources,
          async () =>
            finishAnalysisCommand(
              () =>
                pe.inspect(
                  {
                    path: resolve(args.path),
                    max_file_bytes: options.maxFileBytes,
                    max_entries: options.maxEntries,
                  },
                  { signal },
                ),
              pe,
              "rea-pe-resources",
              "inspect_pe_resources",
            ),
        );
      }),
  });
  cli.command(CLI_COMMANDS.inspectBinaryTriage, {
    description:
      "Triage a file: format, entropy, sections, packer indicators and text aimed at AI analysts",
    args: z.object({ path: z.string().describe("Local file to triage") }),
    options: z.object({
      maxFileBytes: inspectBinaryTriageInputSchema.shape.max_file_bytes,
      minStringLength: inspectBinaryTriageInputSchema.shape.min_string_length,
      maxFindings: inspectBinaryTriageInputSchema.shape.max_findings,
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        const triage = createBinaryTriageService();
        return await logCliCommand(
          logger,
          CLI_COMMANDS.inspectBinaryTriage,
          async () =>
            finishAnalysisCommand(
              () =>
                triage.inspect(
                  {
                    path: resolve(args.path),
                    max_file_bytes: options.maxFileBytes,
                    min_string_length: options.minStringLength,
                    max_findings: options.maxFindings,
                  },
                  { signal },
                ),
              triage,
              "rea-binary-triage",
              "inspect_binary_triage",
            ),
        );
      }),
  });
  cli.command(CLI_COMMANDS.decodeBytes, {
    description:
      "Decode inline bytes or a file range through a deterministic step chain (base64, XOR, RC4, AES, inflate, ...)",
    args: z.object({
      input: z
        .string()
        .describe(
          "Inline JSON or a JSON file with the decode_bytes input: {input, steps, max_bytes?, preview_bytes?}",
        ),
    }),
    run: ({ args }) =>
      withCommandCancellation(async (signal) => {
        const decoding = createByteDecodingService();
        return await logCliCommand(
          logger,
          CLI_COMMANDS.decodeBytes,
          async () => {
            const input = await parseCliJsonInput(args.input, "decode_bytes");
            if (!input.ok) return input.error;
            const value = input.value;
            if (
              typeof value === "object" &&
              value !== null &&
              "input" in value &&
              typeof value.input === "object" &&
              value.input !== null &&
              "path" in value.input &&
              typeof value.input.path === "string"
            )
              value.input.path = resolve(value.input.path);
            return finishAnalysisCommand(
              () => decoding.decode(value, { signal }),
              decoding,
              "rea-byte-decoding",
              "decode_bytes",
            );
          },
        );
      }),
  });
  cli.command(CLI_COMMANDS.convertNumber, {
    description:
      "Show an integer in every base, width, byte order, ASCII and float form",
    args: z.object({
      value: z
        .string()
        .describe(
          "Integer (0x.., 0b.., 0o.., decimal), or hex bytes when --byte-order is given",
        ),
    }),
    options: z.object({
      width: z
        .enum(["8", "16", "32", "64"])
        .optional()
        .describe("Bit width; omitted uses the smallest that holds the value"),
      byteOrder: convertNumberInputSchema.shape.byte_order,
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async () => {
        const decoding = createByteDecodingService();
        return await logCliCommand(
          logger,
          CLI_COMMANDS.convertNumber,
          async () =>
            finishAnalysisCommand(
              () =>
                Promise.resolve(
                  decoding.convert({
                    ...(options.byteOrder === undefined
                      ? { value: args.value }
                      : {
                          bytes_hex: args.value,
                          byte_order: options.byteOrder,
                        }),
                    ...(options.width === undefined
                      ? {}
                      : { width: Number(options.width) }),
                  }),
                ),
              decoding,
              "rea-byte-decoding",
              "convert_number",
            ),
        );
      }),
  });
  cli.command(CLI_COMMANDS.scanWithYara, {
    description:
      "Scan a file with your YARA rules (bundled YARA-X engine); reports rules, offsets and sections",
    args: z.object({ path: z.string().describe("Local file to scan") }),
    options: z.object({
      rules: z
        .array(z.string())
        .optional()
        .describe("YARA rule files; repeat for several"),
      ruleSource: z
        .string()
        .optional()
        .describe("Inline YARA rule source instead of rule files"),
      timeoutMs: scanWithYaraInputSchema.shape.timeout_ms,
      maxMatches: scanWithYaraInputSchema.shape.max_matches,
    }),
    run: ({ args, options }) =>
      withCommandCancellation(async (signal) => {
        const yara = createYaraScanService();
        return await logCliCommand(
          logger,
          CLI_COMMANDS.scanWithYara,
          async () =>
            finishAnalysisCommand(
              () =>
                yara.scan(
                  {
                    path: resolve(args.path),
                    rules:
                      options.ruleSource === undefined
                        ? {
                            kind: "files",
                            paths: (options.rules ?? []).map((path) =>
                              resolve(path),
                            ),
                          }
                        : { kind: "inline", source: options.ruleSource },
                    timeout_ms: options.timeoutMs,
                    max_matches: options.maxMatches,
                  },
                  { signal },
                ),
              yara,
              "rea-yara-x",
              "scan_with_yara",
            ),
        );
      }),
  });
  const service = createBinaryLayoutService(environment);
  cli.command(CLI_COMMANDS.inspectBinaryLayout, {
    description:
      "Inspect binary file/linked layout without executing the selected object",
    args: z.object({
      path: z.string().describe("Local ELF binary or relocatable object"),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectBinaryLayout, async () => {
          const result = await service.inspectAndClose(
            { path: resolve(args.path) },
            { signal },
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
  const recorded = createRecordedCrashService(environment);
  cli.command(CLI_COMMANDS.inspectRecordedCrash, {
    description:
      "Inspect supplied core registers/signals and optional debugger mapping evidence",
    args: z.object({
      path: z
        .string()
        .describe("Local Linux ELF64 amd64 or AArch64 little-endian core"),
    }),
    options: z.object({
      debuggerContext: z
        .boolean()
        .default(false)
        .describe("Add BYO core-only GDB/pwndbg mapping candidates"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectRecordedCrash, async () => {
          const result = await recorded.inspectAndClose(
            {
              path: resolve(args.path),
              include_debugger_context: options.debuggerContext,
            },
            { signal },
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
};
