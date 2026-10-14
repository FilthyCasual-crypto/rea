import type { AnalysisOperation } from "./AnalysisProvider.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";

/** Provider identity for deterministic composed analysis workflows. */
export const REA_WORKFLOW_PROVIDER = {
  id: "rea-workflow",
  name: "Ghostwire composed investigation workflow",
  version: "1",
} as const;

/** Commit a workflow result to its upstream profile and applicable semantic revision. */
export const workflowAnalysisProfile = (
  upstream: AnalysisProfileCommitment,
  operation?: AnalysisOperation,
): AnalysisProfileCommitment =>
  createAnalysisProfile(REA_WORKFLOW_PROVIDER, {
    upstream_analysis_profile: upstream,
    ...(operation === "binary_overview"
      ? { workflow_revision: 3 }
      : operation === "batch_decompile" ||
          operation === "get_call_graph" ||
          operation === "trace_feature"
        ? { workflow_revision: 2 }
        : {}),
  });

/** Provider identity for deterministic artifact inventories. */
export const ARTIFACT_GRAPH_PROVIDER = Object.freeze({
  id: "rea-artifact-graph",
  name: "Ghostwire safe artifact graph provider",
  version: "1",
} as const);

/** Provider identity for execution-free managed PE/CLI analysis. */
export const MANAGED_STATIC_PROVIDER = Object.freeze({
  id: "rea-dotnet-static",
  name: "Ghostwire managed static analysis provider",
  version: "1",
} as const);

/** Provider identity for portable, execution-free PE resource decoding. */
export const PE_RESOURCES_PROVIDER = Object.freeze({
  id: "rea-pe-resources",
  name: "Ghostwire PE resource parser",
  version: "1",
} as const);

/** Provider identity for deterministic managed-code comparison workflows. */
export const MANAGED_WORKFLOW_PROVIDER = {
  id: "rea-dotnet-workflows",
  name: "Ghostwire managed-code workflows",
  version: "1",
} as const;

/** Provider identity for deterministic Apple application projections. */
export const APPLE_APPLICATION_PROVIDER = {
  id: "rea-apple-application",
  name: "Ghostwire Apple application workflows",
  version: "1",
} as const;

/** Provider identity for deterministic Android application projections. */
export const ANDROID_APPLICATION_PROVIDER = {
  id: "rea-android-application",
  name: "Ghostwire Android application workflows",
  version: "1",
} as const;

/** Provider identity for deterministic HarmonyOS application projections. */
export const HARMONY_APPLICATION_PROVIDER = {
  id: "rea-harmony-application",
  name: "Ghostwire HarmonyOS application workflows",
  version: "1",
} as const;

/** Provider identity for verified publication of retained website scripts. */
export const WEB_SCRIPT_EXPORT_PROVIDER = {
  id: "rea-web-script-export",
  name: "Ghostwire captured script export",
  version: "1",
} as const;

/** Provider identity for deterministic static JavaScript application analysis. */
export const JAVASCRIPT_APPLICATION_PROVIDER = {
  id: "rea-javascript-application",
  name: "Ghostwire JavaScript application analyzer",
  version: "1",
} as const;

/** Provider identity for static/passive-runtime JavaScript reconciliation. */
export const JAVASCRIPT_RUNTIME_RECONCILIATION_PROVIDER = {
  id: "rea-javascript-runtime-reconciliation",
  name: "Ghostwire JavaScript runtime reconciliation",
  version: "1",
} as const;

/** Provider identity for selected views of retained analysis Evidence. */
export const ANALYSIS_VIEW_PROVIDER = {
  id: "rea-analysis-view",
  name: "Ghostwire analysis view projection",
  version: "1",
} as const;

/** Provider identity for graph-native feature tracing and version comparison. */
export const JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER = {
  id: "rea-javascript-application-workflows",
  name: "Ghostwire JavaScript application workflows",
  version: "1",
} as const;

/** Provider identity for deterministic cross-artifact comparisons. */
export const ARTIFACT_COMPARISON_PROVIDER = {
  id: "rea-artifact-comparison",
  name: "Ghostwire artifact comparison",
  version: "1",
} as const;

/** Provider identity for deterministic cross-function comparisons. */
export const FUNCTION_COMPARISON_PROVIDER = {
  id: "rea-function-comparison",
  name: "Ghostwire function comparison",
  version: "1",
} as const;

/** Provider identity for deterministic Evidence bundle comparisons. */
export const BUNDLE_COMPARISON_PROVIDER = {
  id: "rea-bundle-comparison",
  name: "Ghostwire Evidence bundle comparison",
  version: "1",
} as const;

/** Provider identity for comparison-Evidence behavior aggregation. */
export const CHANGED_BEHAVIOR_PROVIDER = {
  id: "rea-changed-behavior",
  name: "Ghostwire changed behavior investigation",
  version: "1",
} as const;

/** Provider identity for Evidence-backed call-path reconstruction. */
export const CALL_PATH_PROVIDER = {
  id: "rea-call-path",
  name: "Ghostwire call path reconstruction",
  version: "1",
} as const;

/** Provider identity for explicit static/runtime hypothesis correlation. */
export const STATIC_RUNTIME_PROVIDER = {
  id: "rea-static-runtime-correlation",
  name: "Ghostwire static/runtime correlation",
  version: "1",
} as const;

/** Provider identity for finite reconstruction specification verification. */
export const RECONSTRUCTION_PROVIDER = {
  id: "rea-reconstruction-verifier",
  name: "Ghostwire reconstruction verifier",
  version: "1",
} as const;
