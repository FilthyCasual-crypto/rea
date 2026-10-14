/**
 * Audited upstream JADX release (github.com/skylot/jadx, Apache-2.0). Ghostwire
 * consumes the unmodified `lib/jadx-<version>-all.jar` from the release ZIP
 * through its own bridge; it never downloads or installs the engine.
 */
export const JADX_RELEASE = Object.freeze({
  version: "1.5.6",
  /** Commit the annotated `v1.5.6` tag points to. */
  revision: "28ff15e4ae69950aebea110a13e5ab895d234dfc",
  /** SHA-256 of the JAR file that `REA_JADX_JAR` selects. */
  sha256: "fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b",
  /** Release asset containing the JAR, with GitHub's published SHA-256. */
  archive_url:
    "https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip",
  archive_sha256:
    "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974",
  archive_entry: "lib/jadx-1.5.6-all.jar",
  jar_filename: "jadx-1.5.6-all.jar",
});

/** Identity of Ghostwire's metadata bridge, distinct from the producing engine. */
export const JADX_BRIDGE_IDENTITY = Object.freeze({
  name: "rea-jadx-bridge",
  version: "2",
});

/** Caller setting that selects the upstream JADX JAR. */
export const JADX_JAR_VARIABLE = "REA_JADX_JAR";
/** Deprecated alias, read only when `REA_JADX_JAR` is unset. */
export const JADX_JAR_DEPRECATED_VARIABLE = "REA_JADX_MCP_JAR";

/** Remediation when `REA_JADX_JAR` is missing or not an absolute path. */
export const JADX_JAR_CONFIGURATION_REMEDIATION = `Set REA_JADX_JAR to the absolute path of a caller-supplied upstream JADX ${JADX_RELEASE.version} ${JADX_RELEASE.jar_filename} (inside ${JADX_RELEASE.archive_url}). Ghostwire does not download or install it.`;

/** Remediation when the selected Java runtime cannot satisfy the JADX bridge. */
export const JADX_JAVA_RUNTIME_REMEDIATION =
  "Select a full JDK including jdk.compiler via JAVA_HOME or PATH, then verify it with java --list-modules. Ghostwire does not install Java.";

/** Remediation when a JADX JVM resource override is malformed. */
export const JADX_JVM_OPTIONS_REMEDIATION =
  "Set REA_JADX_HEAP_MIB to a positive integer (heap size in MiB) and REA_JADX_ACTIVE_PROCESSOR_COUNT to a positive integer within the JVM's signed 32-bit range.";

/** Remediation when the host cannot run the Android JADX subprocess. */
export const JADX_UNSUPPORTED_HOST_REMEDIATION =
  "Use Linux, macOS, or Windows x64 with its bundled native controls for Android JADX analysis.";

/** Remediation when the Windows native backend cannot take process ownership. */
export const JADX_WINDOWS_NATIVE_REMEDIATION =
  "Use a matching current Windows x64 Ghostwire package with its bundled native controls. The native failure above identifies the failed constraint; Java installation or registration changes cannot enable a missing native backend.";

/** Remediation when the Java module-listing probe cannot establish the runtime. */
export const JADX_JAVA_PROBE_REMEDIATION =
  "Verify the selected Java launcher with java --list-modules: it must start promptly and emit a concise module listing including a parseable java.base version. Ghostwire does not install Java.";

/** Producing engine identity used by Evidence and the generated product catalog. */
export const JADX_PROVIDER_IDENTITY = Object.freeze({
  id: "jadx",
  name: "JADX",
  version: JADX_RELEASE.version,
});

/** Audited engine coverage, kept outside portable Android semantics. */
export const JADX_LIMITATIONS = [
  "Static decompiler observations do not establish runtime behavior; the APK is never executed.",
  "Method signatures use provider display types; DEX prototypes come from frozen JADX metadata. Display names may be aliases, and overload indices are local to this engine and artifact.",
  "Class inventories use parsed metadata before code generation, including synthetic members that may be omitted from decompiled source. Source positions remain unknown.",
  "Incoming reference totals count JADX using nodes. Direct invoke entries within a using method report raw DEX code-unit offsets and method indexes, but coverage is limited to those nodes and directly matched invokes; it does not establish every possible dynamic or reflective call site.",
  "Manifest summary fields are extracted by Ghostwire's bridge from the decoded manifest JADX produces; that XML is retained for verification. APK signatures, split APKs, native libraries and Android runtime capture are not verified by this provider.",
] as const;
