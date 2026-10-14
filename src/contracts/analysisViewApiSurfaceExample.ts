/** Generated from the two-request apiSurfaceHar fixture through the HAR decoder and view service. */
export const API_SURFACE_EXAMPLE = {
  input: {
    source: {
      kind: "retained-evidence",
      evidence_id:
        "ev_c9b64c77ad1af0c8e7db802b216e0db569705fe01d618de93cd9db67a6a9b5dd",
    },
    view: {
      kind: "api-surface",
      offset: 0,
      limit: 50,
    },
  },
  output: {
    parent_evidence_id:
      "ev_c9b64c77ad1af0c8e7db802b216e0db569705fe01d618de93cd9db67a6a9b5dd",
    parent_operation: "inspect_web_network_capture",
    parent_digest:
      "c9b64c77ad1af0c8e7db802b216e0db569705fe01d618de93cd9db67a6a9b5dd",
    view_digest:
      "fd35e54429dd46fd14ffe11b1e9b1efe3ca2a85df291ea3c538a8d6352e310ec",
    artifact: {
      path: "/fixtures/api-surface.har",
      sha256:
        "bf58e2c06e55bfe7e0628157c4ad027ce0aeb81a10e8edef8a7f95b8e5f14225",
    },
    coverage: {
      status: "page",
      examined: 1,
      total: 1,
      next_offset: null,
      exhausted: true,
    },
    limitations: [
      "Grouping does not establish handler identity, URL-space schemas or causality.",
      "HAR text is producer-decoded Unicode. Original body bytes remain unknown unless content explicitly uses valid base64; declared sizes are preserved independently of retained bytes. mitmproxy 12.2.3 SaveHar may report null optional postData.text; that null is retained and omitted only from the upstream validation copy.",
    ],
    unknowns: [],
    records: {
      examined: 2,
      total: 2,
      excluded: 0,
    },
    templated_groups: 1,
    groups: [
      {
        method: "GET",
        origin: "https://api.example.test",
        path_template: "/users/{numeric}",
        templated_segments: [
          {
            segment_index: 1,
            rule: "numeric",
            basis: "inferred",
            observed_values: ["8812", "9031"],
          },
        ],
        record_ordinals: [0, 1],
        statuses: [200, 404],
        content_types: ["application/json", "text/plain"],
        flags: ["mixed-statuses", "mixed-content-types"],
      },
    ],
    excluded_records: [],
    kind: "api-surface",
    view: {
      kind: "api-surface",
      offset: 0,
      limit: 50,
    },
  },
} as const;
