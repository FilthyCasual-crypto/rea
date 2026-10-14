import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const registeredProfile = async (config: string): Promise<unknown> => {
  const document = JSON.parse(await readFile(config, "utf8")) as {
    mcpServers?: { rea?: { env?: Record<string, string> } };
  };
  return document.mcpServers?.rea?.env?.REA_MCP_INPUT_SCHEMA_PROFILE;
};

cliTest(
  "setup persists the selected input schema profile and keeps it on later runs",
  async ({ cli }) => {
    const home = await createTestTempDirectory("rea-schema-profile-setup-");
    await mkdir(join(home, ".cursor"), { recursive: true });
    const config = join(home, ".cursor", "mcp.json");
    const environment = {
      HOME: home,
      USERPROFILE: home,
      XDG_CONFIG_HOME: join(home, ".config"),
    };
    const setup = (...extra: string[]) =>
      cli.run({
        arguments: [
          "setup",
          "--client",
          "cursor",
          "--skill=false",
          "--yes",
          "--json",
          ...extra,
        ],
        cwd: home,
        environment,
      });

    const compact = await setup("--schema-profile", "compact");
    expect(compact.exitCode, compact.stdout).toBe(0);
    expect(await registeredProfile(config)).toBe("compact");

    const unchanged = await setup();
    expect(unchanged.exitCode, unchanged.stdout).toBe(0);
    expect(await registeredProfile(config)).toBe("compact");

    const full = await setup("--schema-profile", "full");
    expect(full.exitCode, full.stdout).toBe(0);
    expect(await registeredProfile(config)).toBe("full");

    const invalid = await setup("--schema-profile", "tiny");
    expect(invalid.exitCode).not.toBe(0);
    expect(await registeredProfile(config)).toBe("full");
  },
);
