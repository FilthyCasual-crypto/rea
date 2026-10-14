# Upstream analysis engines

REA integrates existing tools through provider adapters. Upstream source remains
unmodified and retains its own license; it is not copied into REA's domain or
application code.

## JADX

- Source: <https://github.com/skylot/jadx>
- Release: `v1.5.6`, commit `28ff15e4ae69950aebea110a13e5ab895d234dfc`
- Release asset: `jadx-1.5.6.zip`, SHA-256
  `545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974`
- Engine file: `lib/jadx-1.5.6-all.jar` inside that ZIP, SHA-256
  `fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b`
- License: Apache-2.0; see the upstream `LICENSE`.
- Release identity: `src/android/JadxRelease.ts`.
- REA integration: REA's own bridge `bridge/android/ReaJadxBridge.java` and the
  adapter in `src/android/`; no upstream patches and no submodule.

The bridge links only against the `jadx.api`/`jadx.core` classes of the
unmodified upstream JAR plus the JDK. It replaces the former
`jadx-headless-mcp` integration and does not use that project's code, its
Kotlin MCP SDK dependency, or Gson.

Normal REA builds and installed npm packages do not require JADX source or a
Gradle build. Supply the separately obtained JAR with `REA_JADX_JAR`
(`REA_JADX_MCP_JAR` remains a deprecated alias); REA never downloads engines
during an analysis operation. The audited release JAR is identified by SHA-256.
A caller-supplied build reporting the supported JADX version retains its actual
digest and an unknown source revision unless its bytes match the audited
release.

When updating: review upstream API changes the bridge links against
(`JadxDecompiler`, `JavaClass`/`JavaMethod`, `ClassNode`/`MethodNode`, plugin
loading and instruction decoding), update the release identity, run the bridge
regression (`tests/conformance/android/ReaJadxMetadataRegression.java`) and the
real APK CLI/MCP lane. Never attribute modified engine bytes to the audited
source revision.

## Public APK fixture

`npm run fixtures:android` (`scripts/fixtures/android/fetch.mjs`) downloads the
upstream JADX release ZIP, extracts `lib/jadx-1.5.6-all.jar`, and downloads Appium
ApiDemos v6.0.18 into ignored `_reference/apk-integration/`. The ZIP, the
extracted JAR and the APK are each checked against fixed SHA-256 values. Fixture
provenance is recorded in `scripts/fixtures/android/apidemos.json`; the source
uses Apache-2.0. This is a static analysis fixture: no emulator, device, SDK
installation or app execution is needed. APKs and JARs are neither tracked nor
included in npm packages.

## Firmware engines

| Engine | Source | Release | Pinned commit | License |
| --- | --- | --- | --- | --- |
| Binwalk | <https://github.com/ReFirmLabs/binwalk> | v3.1.0 | `4fdab3d464d97b68e0af9088df3f9e2e1545b21c` | MIT, upstream `LICENSE` |
| Unblob | <https://github.com/onekey-sec/unblob> | 26.6.4 | `1fcc7a0a584a70a96c31f5a276c20944d199a089` | MIT, upstream `LICENSE` |

Source remains unmodified in `third_party/binwalk` and `third_party/unblob`.
Release records live in `src/firmware/FirmwareRelease.ts`; REA adapters own the
CLI/report interpretation and lifecycle in `src/firmware/`. Caller-supplied
executables retain their actual launcher digest and unknown source revision;
version output alone does not establish source identity. REA does not bundle
extractors or download/install firmware engines during analysis.

On updates: inspect actual pinned CLI and report producers, preserve licenses,
update gitlinks/release records, run report regressions and the real firmware
lane. See [firmware setup and coverage](../docs/firmware-analysis.md).
