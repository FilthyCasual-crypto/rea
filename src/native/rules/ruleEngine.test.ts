import { expect, it } from "vitest";
import {
  compileRules,
  RuleCompileError,
  RuleScanTimeout,
  scanWithRules,
} from "./ruleEngine.js";

const OPTIONS = {
  maxMatchesPerPattern: 1000,
  deadline: Number.MAX_SAFE_INTEGER,
};

const scan = (rules: string, data: string | Buffer, options = OPTIONS) =>
  scanWithRules(
    compileRules([{ namespace: "default", text: rules, label: "rules.yar" }]),
    typeof data === "string" ? Buffer.from(data, "latin1") : data,
    options,
  );
const matched = (rules: string, data: string | Buffer) =>
  scan(rules, data).matches.map(({ rule }) => rule);
const holds = (condition: string, data: string | Buffer, strings = "") =>
  matched(
    `rule r { ${strings ? `strings: ${strings}` : ""} condition: ${condition} }`,
    data,
  ).length === 1;

it("matches text strings and reports every overlapping offset", () => {
  const result = scan('rule r { strings: $a = "aba" condition: $a }', "xababa");
  expect(result.matches[0]!.patterns[0]).toEqual({
    identifier: "$a",
    kind: "text",
    matches: [
      { offset: 1, length: 3 },
      { offset: 3, length: 3 },
    ],
  });
});

it("applies nocase, wide, ascii, fullword and escapes", () => {
  expect(holds("$a", "xxHELLOxx", '$a = "hello" nocase')).toBe(true);
  expect(
    holds("$a", Buffer.from("hello", "utf16le"), '$a = "hello" wide'),
  ).toBe(true);
  expect(holds("$a", "hello", '$a = "hello" wide')).toBe(false);
  expect(holds("$a", "hello", '$a = "hello" wide ascii')).toBe(true);
  expect(holds("$a", "say hello!", '$a = "hello" fullword')).toBe(true);
  expect(holds("$a", "sayhello", '$a = "hello" fullword')).toBe(false);
  expect(holds("$a", "a\tb\x01", '$a = "a\\tb\\x01"')).toBe(true);
});

it("finds xor-encoded text for a single key or a key range", () => {
  const encoded = Buffer.from(
    [..."secret"].map((char) => char.charCodeAt(0) ^ 0x5a),
  );
  expect(holds("$a", encoded, '$a = "secret" xor')).toBe(true);
  expect(holds("$a", encoded, '$a = "secret" xor(0x5a)')).toBe(true);
  expect(holds("$a", encoded, '$a = "secret" xor(1-0x10)')).toBe(false);
});

it("matches hex strings with wildcards, nibbles, jumps and alternatives", () => {
  const bytes = Buffer.from([
    0x4d, 0x5a, 0x90, 0x00, 0x11, 0x22, 0x33, 0xe8, 0xaa,
  ]);
  expect(holds("$a", bytes, "$a = { 4D 5A ?? 00 }")).toBe(true);
  expect(holds("$a", bytes, "$a = { 4D 5? 9? }")).toBe(true);
  expect(holds("$a", bytes, "$a = { 4D [2-4] 11 }")).toBe(true);
  expect(holds("$a", bytes, "$a = { 4D [5] 33 }")).toBe(true);
  expect(holds("$a", bytes, "$a = { 4D [-] AA }")).toBe(true);
  expect(holds("$a", bytes, "$a = { ( 01 02 | 11 22 ) 33 }")).toBe(true);
  expect(holds("$a", bytes, "$a = { 4D 5A 91 }")).toBe(false);
});

it("matches regular expressions with flags", () => {
  expect(holds("$a", "GET /index.php HTTP", "$a = /GET \\/[a-z]+\\.php/")).toBe(
    true,
  );
  expect(holds("$a", "get /x.php", "$a = /GET \\/[a-z]+\\.php/i")).toBe(true);
});

it("evaluates positions, counts, offsets, lengths and ranges", () => {
  const strings = '$a = "MZ" $b = "abc"';
  const data = "MZxxabcxxabc";
  expect(holds("$a at 0", data, strings)).toBe(true);
  expect(holds("$b at 4 and $b in (5..20)", data, strings)).toBe(true);
  expect(holds("#b == 2 and #b in (0..6) == 1", data, strings)).toBe(true);
  expect(holds("@b[2] == 9 and @b == 4 and !b[1] == 3", data, strings)).toBe(
    true,
  );
  expect(holds("@b[3] == 9", data, strings)).toBe(false);
});

it("evaluates quantifiers over them and wildcard sets", () => {
  const strings = '$x1 = "one" $x2 = "two" $y = "three"';
  expect(holds("any of them", "two", strings)).toBe(true);
  expect(holds("all of them", "one two", strings)).toBe(false);
  expect(holds("all of ($x*)", "one two", strings)).toBe(true);
  expect(holds("2 of ($x1, $y)", "one three", strings)).toBe(true);
  expect(holds("none of them", "nothing", strings)).toBe(true);
  expect(holds("any of ($x*) in (0..2)", "one", strings)).toBe(true);
});

it("reads integers in both byte orders and does arithmetic", () => {
  const data = Buffer.from([
    0x4d, 0x5a, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0xff,
  ]);
  expect(holds("uint16(0) == 0x5A4D", data)).toBe(true);
  expect(holds("uint16be(0) == 0x4D5A", data)).toBe(true);
  expect(holds("uint32(uint8(1) - 0x56) == 0x4550", data)).toBe(true);
  expect(holds("int8(8) == -1 and uint8(8) == 255", data)).toBe(true);
  expect(holds("filesize < 1KB and filesize == 9", data)).toBe(true);
  expect(
    holds(
      "(3 * 4 + 1) % 5 == 3 and 7 \\ 2 == 3 and (1 << 4 | 1) == 17 and ~0 == -1",
      data,
    ),
  ).toBe(true);
  expect(holds("uint32(100) == 0", data)).toBe(false);
});

it("applies private, global and rule references", () => {
  const rules = `
    private rule is_mz { condition: uint16(0) == 0x5A4D }
    rule mz_with_marker { strings: $m = "MARK" condition: is_mz and $m }
    rule hidden_string { strings: $p = "MARK" private $q = "Z" condition: all of them }`;
  const result = scan(rules, "MZ..MARK");
  expect(result.matches.map(({ rule }) => rule)).toEqual([
    "mz_with_marker",
    "hidden_string",
  ]);
  expect(
    result.matches[1]!.patterns.map(({ identifier }) => identifier),
  ).toEqual(["$q"]);
  expect(
    matched(
      "global rule gate { condition: filesize > 100 } rule any_file { condition: true }",
      "small",
    ),
  ).toEqual([]);
});

it("reports metadata, tags and anonymous strings", () => {
  const result = scan(
    'rule r : packer upx { meta: author = "me" score = -3 ok = true strings: $ = "UPX!" condition: any of them }',
    "UPX!",
  );
  expect(result.matches[0]).toMatchObject({
    tags: ["packer", "upx"],
    metadata: [
      { identifier: "author", value: "me" },
      { identifier: "score", value: -3 },
      { identifier: "ok", value: true },
    ],
    patterns: [{ identifier: "$" }],
  });
});

it.each([
  ['import "pe" rule r { condition: true }', /modules are not supported/],
  ['include "other.yar"', /include directives/],
  ["rule r { condition: pe.number_of_sections > 1 }", /module field pe/],
  [
    'rule r { strings: $a = "x" condition: for any i in (1..#a) : (@a[i] > 0) }',
    /for loops/,
  ],
  ['rule r { strings: $a = "abc" base64 condition: $a }', /base64/],
  ["rule r { condition: $missing }", /undefined string \$missing/],
  ["rule r { condition: other_rule }", /undefined identifier other_rule/],
  ["rule r { condition: true } rule r { condition: true }", /duplicate rule r/],
  ["rule r { strings: $a = { 4D ~5A } condition: $a }", /negated hex/],
  [
    'rule r { strings: $a = "unterminated condition: $a }',
    /unterminated string/,
  ],
])("rejects %s with a located message", (source, message) => {
  expect(() =>
    compileRules([{ namespace: "n", text: source, label: "rules.yar" }]),
  ).toThrow(RuleCompileError);
  expect(() =>
    compileRules([{ namespace: "n", text: source, label: "rules.yar" }]),
  ).toThrow(message);
  expect(() =>
    compileRules([{ namespace: "n", text: source, label: "rules.yar" }]),
  ).toThrow(/rules\.yar:\d+:\d+:/);
});

it("ignores comments and caps matches per pattern", () => {
  const result = scan(
    '// note\nrule r { /* block */ strings: $a = "a" condition: #a > 2 }',
    "aaaaa",
    {
      maxMatchesPerPattern: 3,
      deadline: Number.MAX_SAFE_INTEGER,
    },
  );
  expect(result.matches[0]!.patterns[0]!.matches).toHaveLength(3);
  expect(result.truncated).toBe(true);
});

it("stops at the deadline", () => {
  expect(() =>
    scan('rule r { strings: $a = "a" condition: $a }', "a".repeat(100000), {
      maxMatchesPerPattern: 1_000_000,
      deadline: Date.now() - 1,
    }),
  ).toThrow(RuleScanTimeout);
});
