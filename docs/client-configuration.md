# Client configuration and troubleshooting

Use this reference when a client's configuration paths, profiles, trust settings,
or schema limits affect REA. Start with [installation and setup](installation.md)
for the reviewed setup transaction and [client IDs](installation.md#supported-agents).
The versioned verification notes below describe their stated runs; live service
acceptance is verified only where explicitly recorded.

## Fiddler Everywhere alongside REA

Connect Fiddler Everywhere's MCP server separately for HTTP traffic debugging,
preserving your REA client entry. See the
[setup instructions and public skills](web-network-captures.md#fiddler-everywhere-mcp-and-public-skills).

## GitHub Copilot CLI

For GitHub Copilot CLI 1.0.95, `gpt-4.1` model metadata can block ordinary
chat with REA's full input-schema profile before sending a model request
(`compaction_static_context_blocked`; [#1554](https://github.com/morluto/rea/issues/1554)).
For the native offline OpenAI-compatible BYOK adapter, full-profile chat and
analysis also passed with a distinct `COPILOT_PROVIDER_MODEL_ID` such as
`rea-gpt-4.1`, `COPILOT_PROVIDER_WIRE_MODEL=gpt-4.1`, and that distinct ID selected
through `copilot --model rea-gpt-4.1`. The local fixture requested
`COPILOT_PROVIDER_MAX_PROMPT_TOKENS=1000000`; configure the limit supported by
your backend. This keeps every full schema and the actual wire model intact.
It does not establish the effective client budget or fix the built-in-ID path.
The existing compact profile passed native chat and analysis with the complete
tool inventory on Linux using a loopback model fixture. After setup, add
`"REA_MCP_INPUT_SCHEMA_PROFILE": "compact"` to the `env` object of the
`mcpServers.rea` entry in Copilot's `mcp-config.json`, preserving its other
settings, then restart the client. Compact advertisements can reduce nested
schema constraints; REA still validates complete canonical inputs. Full-profile
`gpt-5.4` metadata is also verified locally. Live model API acceptance and
Windows remain unverified; see [native client verification](testing.md).

## Claude Desktop

Setup registers `mcpServers.rea` in `claude_desktop_config.json`: under
`~/Library/Application Support/Claude` on macOS, under
`$XDG_CONFIG_HOME/Claude` (default `~/.config/Claude`) on Linux, and on Windows
in the file the installed app reads:

- Without Claude Desktop's MSIX package storage, setup uses
  `%APPDATA%\Claude\claude_desktop_config.json`.
- The MSIX build (package family `Claude_pzs8sxrjxfjjc`, installed under
  `C:\Program Files\WindowsApps\Claude_<version>_x64__pzs8sxrjxfjjc`)
  virtualizes AppData writes. Once it has saved its configuration, it reads
  the package-private copy
  `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json`
  and ignores the `%APPDATA%` file. Setup, doctor and uninstall use that
  private copy when it exists. Before the package has saved one, they use the
  `%APPDATA%` file it still reads; with neither file, setup creates the
  private copy.
- If `%LOCALAPPDATA%\Packages` holds a `Claude_<publisher ID>` package from
  another publisher, or cannot be read, REA cannot establish which file Claude
  Desktop reads. Setup, doctor and uninstall report that instead of falling
  back to `%APPDATA%`. Doctor then reports `claude_desktop` as invalid, and
  uninstall stops before removing anything for any client.

Quit Claude Desktop fully before approving setup; closing its window is not
enough. A running Claude Desktop can rewrite its configuration from memory and
drop the registration. This was observed with the Windows MSIX build. Start
Claude Desktop again after setup. If the package saves its private copy after
setup planned to write the `%APPDATA%` file, setup makes no change and asks you
to rerun it.

A process that the MSIX app started, such as a terminal in Claude Desktop's
Code tab, sees the package's private files at their `%APPDATA%` paths even
though it reports no package identity. Setup compares one of those files at
both paths. When it finds that redirected view, the app is running, so setup
and uninstall refuse to change Claude Desktop's configuration; rerun them from
a terminal that Claude Desktop did not start. If the package has no private
file to compare, setup and uninstall cannot rule that out and also refuse; open
Claude Desktop once if it has never run, quit it fully, then rerun. Doctor
reads the same file from either kind of process.

The same process also writes everything under `%APPDATA%` and
`%LOCALAPPDATA%` into the package's private storage, where other apps never
read it. From that redirected view, setup and uninstall refuse to change other
clients' files there (VS Code, Devin and Hermes) and skill directories
there. `npm install -g` run from such a process installs into the package's
`LocalCache\Roaming\npm`, which other processes cannot see at the `%APPDATA%`
path. Setup refuses to register a launcher stored in any MSIX package's
private storage. Install REA from an ordinary terminal and rerun setup there.

Uninstall removes REA's entry from both the private copy and the `%APPDATA%`
file, including registrations that earlier releases wrote to `%APPDATA%`.

REA recognizes only the MSIX package. A non-MSIX Claude Desktop installed
beside it, which would read the `%APPDATA%` file, is not detected.

The package identity, both file locations, the redirected view, and these
setup and doctor results were observed on Windows 11 with the MSIX build
2.31226.1.0, using read-only `doctor` and `setup --dry-run` runs both inside
and outside the app. On that host, setup run from an ordinary terminal with
the app quit wrote the package-private copy; after the app restarted, the
entry was still present, doctor reported it aligned, and Claude Desktop's MCP
log showed REA starting and answering `tools/list`. Uninstall against the real
app is unverified.

## Claude Code

Claude Code normally defers MCP tool definitions through tool search. It
[turns tool search off](https://code.claude.com/docs/en/mcp#configure-tool-search)
when `ANTHROPIC_BASE_URL` points to a non-first-party Anthropic-compatible
endpoint. It then sends every REA tool's name, description
and input schema with every request
([#2019](https://github.com/morluto/rea/issues/2019)). On main at 04089d5be,
with 172 tools, that payload measured about 496 KB with the default profile and
about 290 KB with `compact`. By the o200k and cl100k tokenizers, that is roughly
120k and 68k tokens. Compaction cannot remove tool definitions. If they nearly
fill the window Claude Code assumes, the context refills after every compaction
and Claude Code reports that autocompact is thrashing. To avoid this:

- Make Claude Code assume the model's actual context window. For unrecognized
  model IDs, set `CLAUDE_CODE_MAX_CONTEXT_TOKENS` to the window the provider
  documents.
- If the endpoint forwards `tool_reference` blocks, set `ENABLE_TOOL_SEARCH=true`
  to restore deferred loading. Endpoints that do not support `tool_reference`
  content blocks will fail requests with this setting.
- To shrink the upfront catalog, add
  `"REA_MCP_INPUT_SCHEMA_PROFILE": "compact"` to the `env` object of the
  `mcpServers.rea` entry in `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json`
  when that variable is set), then restart Claude Code. Setup keeps this
  override.

The sizes above come from REA's own `tools/list`.

For a client whose stdio reader rejects the complete catalog frame, add
`"REA_MCP_OUTPUT_SCHEMA_PROFILE": "off"` to REA's `env` object and restart the
client. This omits only advertised output schemas; REA still validates complete
structured results against its canonical contracts. See [MCP output schema
profiles](mcp-contracts.md#output-schemas).

## Pi

For [Pi](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/mcp.md),
setup writes a `type: "stdio"` entry under `mcpServers.rea` in the user-level
`~/.pi/agent/mcp.json` and installs the bundled skill under `~/.agents/skills`.
Use `rea setup --client pi --dry-run --json` to inspect the plan, then
`rea setup --client pi --yes --json` to approve it. Check the registration with
`rea doctor --client pi --json`. Pi reads `mcp.json` as strict JSON, like its
own loader: comments, trailing commas, a byte-order mark, or an empty existing
file are invalid, and setup reports them instead of rewriting the file. Repair
such a file to plain JSON first, then rerun setup.

Setup follows Pi's `PI_CODING_AGENT_DIR`: unset or empty selects the default;
`~` and `~/` expand to the home directory; absolute paths and file URLs select
that directory; relative paths stay relative to the command's working directory.
On Windows, native paths, `~\`, and Git Bash/MSYS, Cygwin, and WSL drive paths
are normalized as Pi does. Run REA and Pi from the same working directory when
using a relative override. Pi has no profiles: `OMP_PROFILE`, `PI_PROFILE`,
`PI_CONFIG_DIR`, and OMP's `enabledServers`/`disabledServers` lists do not affect
Pi registration. Doctor accepts an omitted `type` for stdio but reports a
non-stdio type as invalid; `enabled: false` stays disabled.

REA configures only the user scope. Pi also reads `.pi/mcp.json` in trusted
projects; a same-name project entry can replace the user entry or override its
enabled state and exposure. Check that file if the user registration is aligned
but unavailable in a project. An extension that registers `/mcp` can replace
Pi's built-in MCP support and use its own configuration instead. Run `/reload`
in an existing Pi session after changing servers outside the session.

## Antigravity

Antigravity 2.0 discovers personal skills in `~/.gemini/config/skills`.
Setup installs its selected skill copy there.

## Gemini CLI

Gemini CLI uses `$GEMINI_CLI_HOME/.gemini/settings.json` when that home override
is nonempty, including its shared personal skills at
`$GEMINI_CLI_HOME/.agents/skills`. Setup and doctor check MCP allow/exclude
policies from system defaults, user settings, trusted workspace settings, and
system overrides. Workspace trust follows `GEMINI_CLI_TRUST_WORKSPACE`,
`GEMINI_RESTRICTED_MODE`, the effective `security.folderTrust.enabled` setting,
and the selected `trustedFolders.json` (including
`GEMINI_CLI_TRUSTED_FOLDERS_PATH`). Settings in an untrusted workspace do not
participate. A workspace or system `mcpServers.rea` replaces the entire user
entry; setup stops if the winning definition conflicts with its planned entry.
Review those files manually: setup never edits administrator/workspace settings
or grants workspace trust. Trust supplied only by a running IDE is outside this
standalone CLI check.

## Codex and Devin

Codex treats an unset or empty `CODEX_HOME` as `~/.codex`. Devin honors
`XDG_CONFIG_HOME` for its `devin/mcp_config.json` on non-Windows systems.

## OMP

For OMP, setup writes a `type: "stdio"` entry to the user-level
`~/.omp/agent/mcp.json`. It follows `PI_CONFIG_DIR` and
`PI_CODING_AGENT_DIR` (relative to the setup working directory), and the profile selected by `OMP_PROFILE` or
`PI_PROFILE` (`~/.omp/profiles/<name>/agent/mcp.json`). Setup also removes
`rea` from that file's `disabledServers` list, which would otherwise hide the
registration. Doctor treats an `enabled: false` entry as active when
`enabledServers` lists `rea`, as OMP does, unless `disabledServers` also lists
it. Run setup under each profile that should load REA.

## Hermes

For Hermes, setup writes a `mcp_servers.rea` entry to `config.yaml`, preserving
comments and unrelated settings. It resolves that file from `HERMES_HOME`, else
from the platform default Hermes itself uses — `%LOCALAPPDATA%\hermes` on
Windows, `~/.hermes` elsewhere — including any `HERMES_DATA_DIR_SUFFIX`. Hermes
connects an entry unless `enabled` is false, so setup states `enabled: true`.

Hermes personal skills install under the active Hermes home's `skills` directory.
Setup, doctor and uninstall follow the root's `active_profile` selection, as
plain Hermes CLI commands do. An explicit `HERMES_HOME` pointing to
`profiles/<name>` selects that named profile directly. An invalid, missing or
deleted sticky profile is reported instead of writing into the default home;
repair the profile or run `hermes profile use default` before retrying.
REA follows `HERMES_HOME` whitespace trimming, environment-variable expansion,
and home expansion before resolving that profile. Setup previews the resolved
configuration and skill destinations; doctor and uninstall use those same paths.

## Factory Droid

For [Factory Droid](https://docs.factory.com/harness/mcp), setup writes
`mcpServers.rea` into the user-level `~/.factory/mcp.json`. Entries carry
`command`, `args`, and `env`. Droid discovers personal skills from
`~/.factory/skills` ([skills](https://docs.factory.com/harness/skills)), so
setup installs its skill copy there.

## Other client settings

For OpenCode, setup writes the V1 `mcp.rea` entry, which OpenCode V1 and V2
both load. If the configuration already uses OpenCode V2's native
`mcp.servers` table, setup registers REA there instead and replaces any earlier
`mcp.rea` entry from REA. Setup honors `OPENCODE_CONFIG_DIR` and
`OPENCODE_CONFIG`, preferring the later-loaded JSONC file when both JSON and
JSONC exist. The ordinary XDG global configuration still participates when a
custom directory is selected. Doctor checks the merged user registration; uninstall removes
REA-owned entries from every applicable user file so an older entry cannot
become active again. Malformed applicable files block setup before changes.

Grok Build loads `[mcp_servers.rea]` from `$GROK_HOME/config.toml`, or from
`~/.grok/config.toml` when `GROK_HOME` is unset or empty. Setup edits that server
table, `[mcp_servers.rea.env]`, and a root `disabled_mcp_servers` entry that
names `rea`. It sets `startup_timeout_sec = 30` and leaves every other name
in that list. The shared skill installed under `~/.agents/skills` is already
on Grok Build's skill path.

Grok Bot (`grok_bot`) is detected from `~/.grokbot`, or from `SAND_DATA_ROOT`
when that value is an absolute path. A relative or empty `SAND_DATA_ROOT`
stays on `~/.grokbot`. That directory is not the connector store. Grok Bot
keeps connectors in the signed-in account and runs them on its hosted
computer. It does not import `mcp.json` from the data directory, and it does
not attach a stdio server running on this machine. Setup does not call the
account connector API, does not write a registration file, and does not report
the data directory as aligned. Ask the Grok Bot chat to add a custom MCP
server named `rea` that runs on the Bot's computer:

```bash
npx -y rea-agents@<version> mcp
```

Do not put credentials in that command or its arguments. `rea doctor --client grok_bot`
reports this manual step. `rea uninstall` does not remove the account connector.
