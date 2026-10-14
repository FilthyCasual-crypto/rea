/**
 * Ghostwire's YARA-compatible rule engine.
 *
 * Parses the commonly used subset of the YARA rule language, compiles string
 * definitions to regular expressions over the file's bytes (read as latin1, so
 * one character is one byte), and evaluates conditions. Features outside the
 * subset fail compilation with a message naming the feature and its line, so
 * a rule never silently evaluates differently from its author's intent.
 */

export class RuleCompileError extends Error {}

export interface PatternMatch {
  readonly offset: number;
  readonly length: number;
}

export interface RuleMatch {
  readonly rule: string;
  readonly namespace: string;
  readonly tags: readonly string[];
  readonly metadata: readonly {
    identifier: string;
    value: string | number | boolean;
  }[];
  readonly patterns: readonly {
    readonly identifier: string;
    readonly kind: "text" | "hex" | "regex";
    readonly matches: readonly PatternMatch[];
  }[];
}

export interface ScanOptions {
  readonly maxMatchesPerPattern: number;
  readonly deadline: number;
}

export class RuleScanTimeout extends Error {}

/* ----------------------------------------------------------------- scanner */

const UNSUPPORTED_KEYWORDS: Readonly<Record<string, string>> = {
  for: "for loops",
  entrypoint: "entrypoint",
  defined: "the defined operator",
};

class Source {
  index = 0;
  constructor(
    readonly text: string,
    readonly label: string,
  ) {}

  fail(message: string, at = this.index): never {
    const before = this.text.slice(0, at);
    const line = before.split("\n").length;
    const column = at - before.lastIndexOf("\n");
    throw new RuleCompileError(`${this.label}:${line}:${column}: ${message}`);
  }

  skip(): void {
    for (;;) {
      const rest = this.text.slice(this.index);
      const space = /^\s+/.exec(rest);
      if (space) {
        this.index += space[0].length;
        continue;
      }
      if (rest.startsWith("//")) {
        const end = this.text.indexOf("\n", this.index);
        this.index = end < 0 ? this.text.length : end + 1;
        continue;
      }
      if (rest.startsWith("/*")) {
        const end = this.text.indexOf("*/", this.index + 2);
        if (end < 0) this.fail("unterminated comment");
        this.index = end + 2;
        continue;
      }
      return;
    }
  }

  peek(pattern: RegExp): string | null {
    this.skip();
    const match = pattern.exec(this.text.slice(this.index));
    return match?.index === 0 ? match[0] : null;
  }

  take(pattern: RegExp): string | null {
    const found = this.peek(pattern);
    if (found !== null) this.index += found.length;
    return found;
  }

  expect(pattern: RegExp, description: string): string {
    const found = this.take(pattern);
    if (found === null) this.fail(`expected ${description}`);
    return found;
  }

  word(value: string): boolean {
    return this.take(new RegExp(`^${value}(?![A-Za-z0-9_])`)) !== null;
  }

  atEnd(): boolean {
    this.skip();
    return this.index >= this.text.length;
  }
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*/;

/* ---------------------------------------------------------- string literal */

const parseQuoted = (source: Source): string => {
  source.skip();
  const start = source.index;
  if (source.text[source.index] !== '"')
    source.fail("expected a quoted string");
  source.index++;
  let value = "";
  for (;;) {
    const char = source.text[source.index];
    if (char === undefined || char === "\n")
      source.fail("unterminated string", start);
    source.index++;
    if (char === '"') return value;
    if (char !== "\\") {
      value += char;
      continue;
    }
    const escape = source.text[source.index++];
    if (escape === "n") value += "\n";
    else if (escape === "t") value += "\t";
    else if (escape === "r") value += "\r";
    else if (escape === '"' || escape === "\\") value += escape;
    else if (escape === "x") {
      const hex = source.text.slice(source.index, source.index + 2);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) source.fail("invalid \\x escape");
      value += String.fromCharCode(Number.parseInt(hex, 16));
      source.index += 2;
    } else source.fail(`unsupported escape \\${escape ?? ""}`);
  }
};

/* ---------------------------------------------------------------- patterns */

interface PatternDefinition {
  readonly identifier: string;
  readonly kind: "text" | "hex" | "regex";
  readonly private: boolean;
  readonly variants: readonly {
    readonly regex: RegExp;
    readonly wide: boolean;
  }[];
  readonly fullword: boolean;
}

const escapeByte = (code: number) => `\\x${code.toString(16).padStart(2, "0")}`;
const literalSource = (bytes: string) =>
  [...bytes].map((char) => escapeByte(char.charCodeAt(0))).join("");
const widen = (bytes: string) => [...bytes].map((char) => `${char}\0`).join("");
const xorWith = (bytes: string, key: number) =>
  [...bytes]
    .map((char) => String.fromCharCode(char.charCodeAt(0) ^ key))
    .join("");

const parseHex = (source: Source): string => {
  const open = source.index;
  source.expect(/^\{/, "{");
  let regex = "";
  const groups: number[] = [];
  for (;;) {
    source.skip();
    const char = source.text[source.index];
    if (char === undefined) source.fail("unterminated hex string", open);
    if (char === "}") {
      if (groups.length > 0) source.fail("unbalanced ( in hex string");
      source.index++;
      if (regex === "") source.fail("empty hex string", open);
      return regex;
    }
    const pair = source.take(/^[0-9A-Fa-f?]{2}/);
    if (pair !== null) {
      const [high, low] = [pair[0]!, pair[1]!];
      if (high === "?" && low === "?") regex += "[\\s\\S]";
      else if (high === "?" || low === "?") {
        const values: string[] = [];
        for (let nibble = 0; nibble < 16; nibble++) {
          const code =
            high === "?"
              ? (nibble << 4) | Number.parseInt(low, 16)
              : (Number.parseInt(high, 16) << 4) | nibble;
          values.push(escapeByte(code));
        }
        regex += `[${values.join("")}]`;
      } else regex += escapeByte(Number.parseInt(pair, 16));
      continue;
    }
    const jump = source.take(/^\[\s*(\d*)\s*(-?)\s*(\d*)\s*\]/);
    if (jump !== null) {
      const [, low = "", dash = "", high = ""] =
        /^\[\s*(\d*)\s*(-?)\s*(\d*)\s*\]/.exec(jump)!;
      if (dash === "") {
        if (low === "") source.fail("empty jump");
        regex += `[\\s\\S]{${low}}`;
      } else regex += `[\\s\\S]{${low === "" ? "0" : low},${high}}`;
      continue;
    }
    if (source.take(/^\(/)) {
      groups.push(regex.length);
      regex += "(?:";
      continue;
    }
    if (source.take(/^\|/)) {
      if (groups.length === 0)
        source.fail("| outside an alternative in hex string");
      regex += "|";
      continue;
    }
    if (source.take(/^\)/)) {
      if (groups.pop() === undefined) source.fail("unbalanced ) in hex string");
      regex += ")";
      continue;
    }
    if (source.take(/^~/))
      source.fail("negated hex bytes (~) are not supported");
    source.fail(`unexpected ${JSON.stringify(char)} in hex string`);
  }
};

const parseRegexLiteral = (source: Source): { body: string; flags: string } => {
  const start = source.index;
  source.index++; // opening slash
  let body = "";
  let inClass = false;
  for (;;) {
    const char = source.text[source.index];
    if (char === undefined || char === "\n")
      source.fail("unterminated regular expression", start);
    source.index++;
    if (char === "\\") {
      body += char + (source.text[source.index++] ?? "");
      continue;
    }
    if (char === "[") inClass = true;
    else if (char === "]") inClass = false;
    else if (char === "/" && !inClass) break;
    body += char;
  }
  const flags = /^[is]*/.exec(source.text.slice(source.index))![0];
  source.index += flags.length;
  return { body, flags };
};

interface Modifiers {
  nocase: boolean;
  wide: boolean;
  ascii: boolean;
  fullword: boolean;
  private: boolean;
  xor: readonly [number, number] | null;
}

const parseModifiers = (
  source: Source,
  kind: "text" | "hex" | "regex",
): Modifiers => {
  const modifiers: Modifiers = {
    nocase: false,
    wide: false,
    ascii: false,
    fullword: false,
    private: false,
    xor: null,
  };
  for (;;) {
    const at = source.index;
    const name = source.peek(IDENTIFIER);
    if (name === null) return modifiers;
    if (name === "condition" || name === "strings" || name === "meta")
      return modifiers;
    if (
      name === "private" ||
      name === "nocase" ||
      name === "wide" ||
      name === "ascii" ||
      name === "fullword"
    ) {
      source.take(IDENTIFIER);
      if (kind === "hex" && name !== "private")
        source.fail(`modifier ${name} is not valid on hex strings`, at);
      if (kind === "regex" && name === "wide")
        source.fail(
          "the wide modifier on regular expressions is not supported",
          at,
        );
      modifiers[name] = true;
      continue;
    }
    if (name === "xor") {
      source.take(IDENTIFIER);
      if (kind !== "text") source.fail("xor is only valid on text strings", at);
      let range: [number, number] = [0, 255];
      if (source.take(/^\(/)) {
        const low = Number(
          source.expect(/^(0x[0-9a-fA-F]+|\d+)/, "an xor key"),
        );
        const high = source.take(/^-/)
          ? Number(source.expect(/^(0x[0-9a-fA-F]+|\d+)/, "an xor key"))
          : low;
        source.expect(/^\)/, ")");
        if (!(low >= 0 && high <= 255 && low <= high))
          source.fail("xor range must be within 0-255", at);
        range = [low, high];
      }
      modifiers.xor = range;
      continue;
    }
    if (name === "base64" || name === "base64wide")
      source.fail(`the ${name} modifier is not supported`, at);
    return modifiers;
  }
};

const compilePattern = (
  source: Source,
  identifier: string,
): PatternDefinition => {
  source.skip();
  const first = source.text[source.index];
  if (first === '"') {
    const bytes = parseQuoted(source);
    if (bytes === "") source.fail("empty text string");
    const modifiers = parseModifiers(source, "text");
    if (modifiers.xor !== null && modifiers.nocase)
      source.fail("xor cannot be combined with nocase");
    const forms: { bytes: string; wide: boolean }[] = [];
    if (modifiers.ascii || !modifiers.wide) forms.push({ bytes, wide: false });
    if (modifiers.wide) forms.push({ bytes: widen(bytes), wide: true });
    const variants = forms.flatMap(({ bytes: form, wide }) => {
      const keys =
        modifiers.xor === null
          ? [0]
          : Array.from(
              { length: modifiers.xor[1] - modifiers.xor[0] + 1 },
              (_, index) => modifiers.xor![0] + index,
            );
      const alternatives = [
        ...new Set(keys.map((key) => literalSource(xorWith(form, key)))),
      ];
      return [
        {
          regex: new RegExp(
            alternatives.join("|"),
            `g${modifiers.nocase ? "i" : ""}`,
          ),
          wide,
        },
      ];
    });
    return {
      identifier,
      kind: "text",
      private: modifiers.private,
      variants,
      fullword: modifiers.fullword,
    };
  }
  if (first === "{") {
    const body = parseHex(source);
    const modifiers = parseModifiers(source, "hex");
    return {
      identifier,
      kind: "hex",
      private: modifiers.private,
      variants: [{ regex: new RegExp(body, "g"), wide: false }],
      fullword: false,
    };
  }
  if (first === "/") {
    const start = source.index;
    const { body, flags } = parseRegexLiteral(source);
    const modifiers = parseModifiers(source, "regex");
    let regex: RegExp;
    try {
      regex = new RegExp(
        body,
        `g${flags.includes("i") || modifiers.nocase ? "i" : ""}${flags.includes("s") ? "s" : ""}`,
      );
    } catch (cause) {
      source.fail(
        `invalid regular expression: ${cause instanceof Error ? cause.message : String(cause)}`,
        start,
      );
    }
    return {
      identifier,
      kind: "regex",
      private: modifiers.private,
      variants: [{ regex, wide: false }],
      fullword: modifiers.fullword,
    };
  }
  return source.fail("expected a text, hex or regular-expression string");
};

/* ------------------------------------------------------------- expressions */

type Value = bigint | boolean | string | null;

interface Context {
  readonly data: string;
  readonly bytes: Uint8Array;
  readonly matches: ReadonlyMap<string, readonly PatternMatch[]>;
  readonly rules: ReadonlyMap<string, boolean>;
}

type Node = (context: Context) => Value;

const truthy = (value: Value): boolean =>
  value === null
    ? false
    : typeof value === "bigint"
      ? value !== 0n
      : typeof value === "string"
        ? value.length > 0
        : value;

const integer = (value: Value): bigint | null =>
  typeof value === "bigint"
    ? value
    : typeof value === "boolean"
      ? value
        ? 1n
        : 0n
      : null;

interface RuleScope {
  readonly patterns: readonly string[];
  readonly rules: ReadonlySet<string>;
}

class ExpressionParser {
  constructor(
    readonly source: Source,
    readonly scope: RuleScope,
  ) {}

  parse(): Node {
    return this.or();
  }

  private or(): Node {
    let left = this.and();
    while (this.source.word("or")) {
      const [a, b] = [left, this.and()];
      left = (context) => truthy(a(context)) || truthy(b(context));
    }
    return left;
  }

  private and(): Node {
    let left = this.not();
    while (this.source.word("and")) {
      const [a, b] = [left, this.not()];
      left = (context) => truthy(a(context)) && truthy(b(context));
    }
    return left;
  }

  private not(): Node {
    if (this.source.word("not")) {
      const operand = this.not();
      return (context) => !truthy(operand(context));
    }
    return this.comparison();
  }

  private comparison(): Node {
    const left = this.bitOr();
    const operator =
      this.source.take(/^(==|!=|<=|>=|<|>)/) ??
      (this.source.word("contains") ? "contains" : null) ??
      (this.source.word("icontains") ? "icontains" : null) ??
      (this.source.word("startswith") ? "startswith" : null) ??
      (this.source.word("endswith") ? "endswith" : null) ??
      (this.source.word("matches") ? "matches" : null);
    if (operator === null) return left;
    if (operator === "matches") {
      this.source.skip();
      if (this.source.text[this.source.index] !== "/")
        this.source.fail("expected a regular expression after matches");
      const { body, flags } = parseRegexLiteral(this.source);
      const regex = new RegExp(body, flags);
      return (context) => {
        const value = left(context);
        return typeof value === "string" ? regex.test(value) : null;
      };
    }
    const right = this.bitOr();
    return (context) => {
      const [a, b] = [left(context), right(context)];
      if (a === null || b === null) return false;
      if (typeof a === "string" || typeof b === "string") {
        if (typeof a !== "string" || typeof b !== "string") return false;
        switch (operator) {
          case "==":
            return a === b;
          case "!=":
            return a !== b;
          case "contains":
            return a.includes(b);
          case "icontains":
            return a.toLowerCase().includes(b.toLowerCase());
          case "startswith":
            return a.startsWith(b);
          case "endswith":
            return a.endsWith(b);
          default:
            return false;
        }
      }
      const [x, y] = [integer(a)!, integer(b)!];
      switch (operator) {
        case "==":
          return x === y;
        case "!=":
          return x !== y;
        case "<":
          return x < y;
        case "<=":
          return x <= y;
        case ">":
          return x > y;
        case ">=":
          return x >= y;
        default:
          return false;
      }
    };
  }

  private binary(
    next: () => Node,
    operators: RegExp,
    apply: (op: string, a: bigint, b: bigint) => bigint | null,
  ): Node {
    let left = next();
    for (;;) {
      const operator = this.source.take(operators);
      if (operator === null) return left;
      const [a, b] = [left, next()];
      left = (context) => {
        const [x, y] = [integer(a(context)), integer(b(context))];
        return x === null || y === null ? null : apply(operator, x, y);
      };
    }
  }

  private bitOr = (): Node =>
    this.binary(
      () => this.bitXor(),
      /^\|(?!\|)/,
      (_, a, b) => a | b,
    );
  private bitXor = (): Node =>
    this.binary(
      () => this.bitAnd(),
      /^\^/,
      (_, a, b) => a ^ b,
    );
  private bitAnd = (): Node =>
    this.binary(
      () => this.shift(),
      /^&(?!&)/,
      (_, a, b) => a & b,
    );
  private shift = (): Node =>
    this.binary(
      () => this.additive(),
      /^(<<|>>)/,
      (op, a, b) => (b < 0n ? null : op === "<<" ? a << b : a >> b),
    );
  private additive = (): Node =>
    this.binary(
      () => this.multiplicative(),
      /^[+-]/,
      (op, a, b) => (op === "+" ? a + b : a - b),
    );
  private multiplicative = (): Node =>
    this.binary(
      () => this.unary(),
      /^(\*|\\|%)/,
      (op, a, b) =>
        op === "*" ? a * b : b === 0n ? null : op === "\\" ? a / b : a % b,
    );

  private unary(): Node {
    if (this.source.take(/^-/)) {
      const operand = this.unary();
      return (context) => {
        const value = integer(operand(context));
        return value === null ? null : -value;
      };
    }
    if (this.source.take(/^~/)) {
      const operand = this.unary();
      return (context) => {
        const value = integer(operand(context));
        return value === null ? null : ~value;
      };
    }
    return this.primary();
  }

  private number(): bigint | null {
    const text = this.source.take(
      /^(0x[0-9a-fA-F]+|0o[0-7]+|\d+)(KB|MB)?(?![A-Za-z0-9_])/,
    );
    if (text === null) return null;
    const [, digits = "", unit] =
      /^(0x[0-9a-fA-F]+|0o[0-7]+|\d+)(KB|MB)?$/.exec(text)!;
    const value = BigInt(digits);
    return unit === "KB"
      ? value * 1024n
      : unit === "MB"
        ? value * 1048576n
        : value;
  }

  private patternSet(): string[] {
    if (this.source.word("them")) return [...this.scope.patterns];
    this.source.expect(/^\(/, "( or them");
    const selected = new Set<string>();
    do {
      const name = this.source.expect(
        /^\$[A-Za-z0-9_]*\*?/,
        "a string identifier",
      );
      const prefix = name.endsWith("*") ? name.slice(0, -1) : null;
      const found =
        prefix === null
          ? this.scope.patterns.filter((pattern) => pattern === name)
          : this.scope.patterns.filter((pattern) => pattern.startsWith(prefix));
      if (found.length === 0) this.source.fail(`undefined string ${name}`);
      for (const pattern of found) selected.add(pattern);
    } while (this.source.take(/^,/));
    this.source.expect(/^\)/, ")");
    return [...selected];
  }

  private quantifier(kind: "any" | "all" | "none" | bigint): Node {
    this.source.expect(/^of(?![A-Za-z0-9_])/, "of");
    const set = this.patternSet();
    let condition: ((context: Context, pattern: string) => boolean) | null =
      null;
    if (this.source.word("in")) {
      const range = this.range();
      condition = (context, pattern) => {
        const bounds = range(context);
        return (
          bounds !== null &&
          (context.matches.get(pattern) ?? []).some(
            ({ offset }) => offset >= bounds[0] && offset <= bounds[1],
          )
        );
      };
    } else if (this.source.word("at")) {
      const at = this.unary();
      condition = (context, pattern) => {
        const position = integer(at(context));
        return (
          position !== null &&
          (context.matches.get(pattern) ?? []).some(
            ({ offset }) => BigInt(offset) === position,
          )
        );
      };
    }
    return (context) => {
      const hits = set.filter((pattern) =>
        condition === null
          ? (context.matches.get(pattern)?.length ?? 0) > 0
          : condition(context, pattern),
      ).length;
      if (kind === "any") return hits >= 1;
      if (kind === "all") return hits === set.length;
      if (kind === "none") return hits === 0;
      return BigInt(hits) >= kind;
    };
  }

  private range(): (context: Context) => [number, number] | null {
    this.source.expect(/^\(/, "(");
    const low = this.parse();
    this.source.expect(/^\.\./, "..");
    const high = this.parse();
    this.source.expect(/^\)/, ")");
    return (context) => {
      const [a, b] = [integer(low(context)), integer(high(context))];
      return a === null || b === null ? null : [Number(a), Number(b)];
    };
  }

  private patternReference(prefix: string): string {
    const name = this.source.expect(
      new RegExp(`^\\${prefix}[A-Za-z0-9_]*`),
      "a string identifier",
    );
    const pattern = `$${name.slice(1)}`;
    if (pattern === "$")
      this.source.fail(
        "anonymous strings can only be used through them or a set",
      );
    if (!this.scope.patterns.includes(pattern))
      this.source.fail(`undefined string ${pattern}`);
    return pattern;
  }

  private primary(): Node {
    const source = this.source;
    if (source.take(/^\(/)) {
      const inner = this.parse();
      source.expect(/^\)/, ")");
      return inner;
    }
    for (const kind of ["any", "all", "none"] as const)
      if (source.word(kind)) return this.quantifier(kind);
    const number = this.number();
    if (number !== null) {
      if (source.peek(/^of(?![A-Za-z0-9_])/)) return this.quantifier(number);
      if (source.take(/^%/))
        source.fail("percentage quantifiers are not supported");
      return () => number;
    }
    if (source.word("true")) return () => true;
    if (source.word("false")) return () => false;
    if (source.word("filesize"))
      return (context) => BigInt(context.bytes.length);
    if (source.peek(/^"/)) {
      const text = parseQuoted(source);
      return () => text;
    }
    if (source.peek(/^\$/)) {
      const pattern = this.patternReference("$");
      if (source.word("at")) {
        const at = this.unary();
        return (context) => {
          const position = integer(at(context));
          return (
            position !== null &&
            (context.matches.get(pattern) ?? []).some(
              ({ offset }) => BigInt(offset) === position,
            )
          );
        };
      }
      if (source.word("in")) {
        const range = this.range();
        return (context) => {
          const bounds = range(context);
          return (
            bounds !== null &&
            (context.matches.get(pattern) ?? []).some(
              ({ offset }) => offset >= bounds[0] && offset <= bounds[1],
            )
          );
        };
      }
      return (context) => (context.matches.get(pattern)?.length ?? 0) > 0;
    }
    if (source.peek(/^#/)) {
      const pattern = this.patternReference("#");
      if (source.word("in")) {
        const range = this.range();
        return (context) => {
          const bounds = range(context);
          return bounds === null
            ? null
            : BigInt(
                (context.matches.get(pattern) ?? []).filter(
                  ({ offset }) => offset >= bounds[0] && offset <= bounds[1],
                ).length,
              );
        };
      }
      return (context) => BigInt(context.matches.get(pattern)?.length ?? 0);
    }
    for (const [sigil, field] of [
      ["@", "offset"],
      ["!", "length"],
    ] as const)
      if (source.peek(new RegExp(`^\\${sigil}`))) {
        const pattern = this.patternReference(sigil);
        let index: Node = () => 1n;
        if (source.take(/^\[/)) {
          index = this.parse();
          source.expect(/^\]/, "]");
        }
        return (context) => {
          const position = integer(index(context));
          const match =
            position === null
              ? undefined
              : (context.matches.get(pattern) ?? [])[Number(position) - 1];
          return match === undefined ? null : BigInt(match[field]);
        };
      }
    const reader = source.take(/^(u?int(8|16|32)(be)?)(?=\s*\()/);
    if (reader !== null) {
      const [, , bits = "8", big] = /^(u?int(8|16|32)(be)?)$/.exec(reader)!;
      const width = Number(bits) / 8;
      const signed = !reader.startsWith("u");
      source.expect(/^\(/, "(");
      const offset = this.parse();
      source.expect(/^\)/, ")");
      return (context) => {
        const at = integer(offset(context));
        if (
          at === null ||
          at < 0n ||
          at + BigInt(width) > BigInt(context.bytes.length)
        )
          return null;
        const view = new DataView(
          context.bytes.buffer,
          context.bytes.byteOffset + Number(at),
          width,
        );
        const little = big === undefined;
        const value =
          width === 1
            ? signed
              ? view.getInt8(0)
              : view.getUint8(0)
            : width === 2
              ? signed
                ? view.getInt16(0, little)
                : view.getUint16(0, little)
              : signed
                ? view.getInt32(0, little)
                : view.getUint32(0, little);
        return BigInt(value);
      };
    }
    const identifier = source.peek(IDENTIFIER);
    if (identifier !== null) {
      if (UNSUPPORTED_KEYWORDS[identifier] !== undefined)
        source.fail(`${UNSUPPORTED_KEYWORDS[identifier]} are not supported`);
      if (
        source.text
          .slice(source.index + identifier.length)
          .trimStart()
          .startsWith(".")
      )
        source.fail(
          `module field ${identifier}.… is not supported; modules are not available`,
        );
      source.take(IDENTIFIER);
      if (!this.scope.rules.has(identifier))
        source.fail(`undefined identifier ${identifier}`);
      return (context) => context.rules.get(identifier) ?? false;
    }
    return source.fail("expected an expression");
  }
}

/* ------------------------------------------------------------------- rules */

interface CompiledRule {
  readonly name: string;
  readonly namespace: string;
  readonly tags: readonly string[];
  readonly metadata: RuleMatch["metadata"];
  readonly isPrivate: boolean;
  readonly isGlobal: boolean;
  readonly patterns: readonly PatternDefinition[];
  readonly condition: Node;
}

export interface CompiledRules {
  readonly rules: readonly CompiledRule[];
}

/** Compile rule sources; each source is its own namespace. */
export const compileRules = (
  sources: readonly {
    readonly namespace: string;
    readonly text: string;
    readonly label: string;
  }[],
): CompiledRules => {
  const rules: CompiledRule[] = [];
  for (const { namespace, text, label } of sources) {
    const source = new Source(text, label);
    const defined = new Set<string>();
    while (!source.atEnd()) {
      if (source.word("import"))
        source.fail(
          `modules are not supported (import ${source.peek(/^"[^"]*"/) ?? ""})`,
        );
      if (source.word("include"))
        source.fail(
          "include directives are not supported; pass each rule file explicitly",
        );
      let isPrivate = false;
      let isGlobal = false;
      for (;;) {
        if (source.word("private")) isPrivate = true;
        else if (source.word("global")) isGlobal = true;
        else break;
      }
      if (!source.word("rule")) source.fail("expected rule");
      const nameAt = source.index;
      const name = source.expect(IDENTIFIER, "a rule name");
      if (defined.has(name)) source.fail(`duplicate rule ${name}`, nameAt);
      const tags: string[] = [];
      if (source.take(/^:/)) {
        for (;;) {
          const tag = source.peek(IDENTIFIER);
          if (tag === null || source.peek(/^\{/)) break;
          tags.push(source.expect(IDENTIFIER, "a tag"));
        }
      }
      source.expect(/^\{/, "{");
      const metadata: {
        identifier: string;
        value: string | number | boolean;
      }[] = [];
      if (source.word("meta")) {
        source.expect(/^:/, ":");
        while (!source.peek(/^(strings|condition)(?![A-Za-z0-9_])/)) {
          const identifier = source.expect(IDENTIFIER, "a metadata identifier");
          source.expect(/^=/, "=");
          let value: string | number | boolean;
          if (source.peek(/^"/)) value = parseQuoted(source);
          else if (source.word("true")) value = true;
          else if (source.word("false")) value = false;
          else {
            const negative = source.take(/^-/) !== null;
            const digits = source.expect(
              /^(0x[0-9a-fA-F]+|\d+)/,
              "a metadata value",
            );
            value = (negative ? -1 : 1) * Number(digits);
          }
          metadata.push({ identifier, value });
        }
      }
      const patterns: PatternDefinition[] = [];
      let anonymous = 0;
      if (source.word("strings")) {
        source.expect(/^:/, ":");
        while (source.peek(/^\$/)) {
          const at = source.index;
          let identifier = source.expect(
            /^\$[A-Za-z0-9_]*/,
            "a string identifier",
          );
          source.expect(/^=/, "=");
          if (identifier === "$") identifier = `$__anonymous_${anonymous++}`;
          else if (
            patterns.some((pattern) => pattern.identifier === identifier)
          )
            source.fail(`duplicate string ${identifier}`, at);
          patterns.push(compilePattern(source, identifier));
        }
      }
      if (!source.word("condition")) source.fail("expected condition");
      source.expect(/^:/, ":");
      const condition = new ExpressionParser(source, {
        patterns: patterns.map(({ identifier }) => identifier),
        rules: defined,
      }).parse();
      source.expect(/^\}/, "}");
      defined.add(name);
      rules.push({
        name,
        namespace,
        tags,
        metadata,
        isPrivate,
        isGlobal,
        patterns,
        condition,
      });
    }
  }
  return { rules };
};

const WORD = /[A-Za-z0-9_]/;

const findMatches = (
  data: string,
  pattern: PatternDefinition,
  options: ScanOptions,
): { matches: PatternMatch[]; truncated: boolean } => {
  const matches: PatternMatch[] = [];
  let truncated = false;
  for (const { regex, wide } of pattern.variants) {
    regex.lastIndex = 0;
    let found: RegExpExecArray | null;
    let steps = 0;
    while ((found = regex.exec(data)) !== null) {
      if (++steps % 4096 === 0 && Date.now() > options.deadline)
        throw new RuleScanTimeout();
      const { index } = found;
      const length = found[0].length;
      regex.lastIndex = index + 1;
      if (length === 0) continue;
      if (pattern.fullword) {
        const step = wide ? 2 : 1;
        const before = data[index - step];
        const after = data[index + length];
        if (
          (before !== undefined &&
            WORD.test(before) &&
            (!wide || data[index - 1] === "\0")) ||
          (after !== undefined && WORD.test(after))
        )
          continue;
      }
      if (matches.length === options.maxMatchesPerPattern) {
        truncated = true;
        break;
      }
      matches.push({ offset: index, length });
    }
  }
  matches.sort((left, right) => left.offset - right.offset);
  return { matches, truncated };
};

/** Scan bytes with compiled rules; returns public matches in definition order. */
export const scanWithRules = (
  compiled: CompiledRules,
  bytes: Uint8Array,
  options: ScanOptions,
): { matches: RuleMatch[]; truncated: boolean } => {
  const data = Buffer.from(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength,
  ).toString("latin1");
  let truncated = false;
  const results = new Map<
    string,
    {
      rule: CompiledRule;
      matched: boolean;
      patterns: Map<string, PatternMatch[]>;
    }
  >();
  const byNamespace = new Map<string, Map<string, boolean>>();
  for (const rule of compiled.rules) {
    if (Date.now() > options.deadline) throw new RuleScanTimeout();
    const patterns = new Map<string, PatternMatch[]>();
    for (const pattern of rule.patterns) {
      const found = findMatches(data, pattern, options);
      truncated ||= found.truncated;
      patterns.set(pattern.identifier, found.matches);
    }
    const ruleResults =
      byNamespace.get(rule.namespace) ?? new Map<string, boolean>();
    byNamespace.set(rule.namespace, ruleResults);
    const matched = truthy(
      rule.condition({ data, bytes, matches: patterns, rules: ruleResults }),
    );
    ruleResults.set(rule.name, matched);
    results.set(`${rule.namespace}:${rule.name}`, { rule, matched, patterns });
  }
  // A false global rule makes every rule in its namespace false.
  const failedGlobal = new Set(
    [...results.values()]
      .filter(({ rule, matched }) => rule.isGlobal && !matched)
      .map(({ rule }) => rule.namespace),
  );
  const matches: RuleMatch[] = [];
  for (const { rule, matched, patterns } of results.values()) {
    if (!matched || rule.isPrivate || failedGlobal.has(rule.namespace))
      continue;
    matches.push({
      rule: rule.name,
      namespace: rule.namespace,
      tags: rule.tags,
      metadata: rule.metadata,
      patterns: rule.patterns
        .filter(
          (pattern) =>
            !pattern.private &&
            (patterns.get(pattern.identifier)?.length ?? 0) > 0,
        )
        .map((pattern) => ({
          identifier: pattern.identifier.startsWith("$__anonymous_")
            ? "$"
            : pattern.identifier,
          kind: pattern.kind,
          matches: patterns.get(pattern.identifier) ?? [],
        })),
    });
  }
  return { matches, truncated };
};
