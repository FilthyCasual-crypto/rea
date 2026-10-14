import type {
  AnalystDirectedTextFinding,
  analystDirectedTextCategorySchema,
} from "./native/binaryTriage.js";
import type { z } from "zod";

type Category = z.infer<typeof analystDirectedTextCategorySchema>;

interface Rule {
  readonly id: string;
  readonly category: Category;
  readonly pattern: string;
}

// Each rule matches text that addresses a model or analyst rather than a
// program's own users. Patterns stay narrow: a finding is a signal for review,
// so ordinary UI strings ("Do not close this window") must not match.
const RULES: readonly Rule[] = [
  {
    id: "chatml-token",
    category: "chat-template-token",
    pattern: String.raw`<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id)\|>`,
  },
  {
    id: "inst-token",
    category: "chat-template-token",
    pattern: String.raw`\[/?INST\]|<</?SYS>>|<(?:start|end)_of_turn>`,
  },
  {
    id: "markdown-role-header",
    category: "chat-template-token",
    pattern: String.raw`###\s*(?:Instruction|System|Response)\s*:`,
  },
  {
    id: "ignore-previous-instructions",
    category: "instruction-override",
    pattern: String.raw`\b(?:ignore|disregard|forget)\s+(?:(?:all|any)\s+)?(?:of\s+)?(?:(?:the|your)\s+)?(?:previous|prior|above|earlier|preceding|original|system)\s+(?:instructions?|prompts?|rules|guidelines|directives)\b`,
  },
  {
    id: "new-instructions",
    category: "instruction-override",
    pattern: String.raw`\b(?:new|updated|real|actual) (?:system )?instructions?\s*:`,
  },
  {
    id: "you-are-ai-role",
    category: "role-assignment",
    pattern: String.raw`\byou are (?:now )?(?:an?|the) (?:ai|assistant|language model|llm|(?:malware |security |binary )?analy[sz]er|(?:malware |security )?analyst|security researcher|reverse engineer)\b`,
  },
  {
    id: "address-ai",
    category: "role-assignment",
    pattern: String.raw`\b(?:dear|attention|note to(?: the)?|hello|hey) (?:ai|llm|chatgpt|claude|gpt|gemini|copilot|assistant|language model|ai (?:assistant|analyst|model))\b`,
  },
  {
    id: "do-not-analyze",
    category: "analysis-suppression",
    pattern: String.raw`\b(?:do not|don't|never|refuse to|stop) (?:analy[sz](?:e|ing)|reverse[- ]engineer(?:ing)?|decompil(?:e|ing)|disassembl(?:e|ing)|investigat(?:e|ing)) (?:this|me|it|(?:the|my|our) (?:file|sample|binary|program|code|executable|payload|software))\b`,
  },
  {
    id: "end-analysis",
    category: "analysis-suppression",
    pattern: String.raw`\b(?:skip|halt|end|terminate|abort|stop) (?:your|this) (?:analysis|investigation)\b`,
  },
  {
    id: "target-is-benign",
    category: "verdict-assertion",
    pattern: String.raw`\b(?:this|the) (?:file|sample|binary|program|executable|software|code|application|payload) is (?:safe|benign|clean|legitimate|harmless|trusted|not malicious|not malware)\b`,
  },
  {
    id: "classify-as-benign",
    category: "verdict-assertion",
    pattern: String.raw`\b(?:classify|mark|report|label|treat) (?:this|it|the (?:file|sample|binary)) as (?:safe|benign|clean|legitimate|harmless|trusted)\b`,
  },
  {
    id: "no-malware-found",
    category: "verdict-assertion",
    pattern: String.raw`\bno malware (?:detected|found|present)\b`,
  },
  {
    id: "tool-call-markup",
    category: "tool-invocation-request",
    pattern: String.raw`<(?:tool_call|function_call|invoke|function_calls)\b|"(?:tool_calls|function_call)"\s*:`,
  },
];

const COMBINED = new RegExp(
  RULES.map((rule, index) => `(?<r${index}>${rule.pattern})`).join("|"),
  "gi",
);

const EXCERPT_CONTEXT = 48;
const MAX_RUN_CHARACTERS = 4096;
const CANCEL_CHECK_INTERVAL = 4096;

export interface AnalystDirectedTextScan {
  readonly findings: AnalystDirectedTextFinding[];
  readonly scanned_strings: number;
  readonly truncated: boolean;
}

interface TextRun {
  readonly text: string;
  readonly offset: number;
  readonly encoding: "ascii" | "utf-16le";
}

const printable = (byte: number): boolean =>
  (byte >= 0x20 && byte <= 0x7e) || byte === 0x09;

/** Yield printable ASCII runs, split at a fixed width so matches stay local. */
function* asciiRuns(bytes: Uint8Array, minimum: number): Generator<TextRun> {
  let start = -1;
  for (let index = 0; index <= bytes.length; index++) {
    const inside = index < bytes.length && printable(bytes[index]!);
    if (inside && start < 0) start = index;
    if (start >= 0 && (!inside || index - start === MAX_RUN_CHARACTERS)) {
      if (index - start >= minimum)
        yield {
          text: Buffer.from(bytes.subarray(start, index)).toString("latin1"),
          offset: start,
          encoding: "ascii",
        };
      start = inside ? index : -1;
    }
  }
}

/** Yield printable UTF-16LE runs at both byte alignments. */
function* utf16Runs(bytes: Uint8Array, minimum: number): Generator<TextRun> {
  for (const alignment of [0, 1]) {
    let start = -1;
    let characters = "";
    // One step past the last complete code unit flushes a run that reaches
    // the end of the file.
    for (let index = alignment; index <= bytes.length; index += 2) {
      const inside =
        index + 1 < bytes.length &&
        bytes[index + 1] === 0 &&
        printable(bytes[index]!);
      if (inside) {
        if (start < 0) start = index;
        characters += String.fromCharCode(bytes[index]!);
      }
      if (start >= 0 && (!inside || characters.length === MAX_RUN_CHARACTERS)) {
        if (characters.length >= minimum)
          yield { text: characters, offset: start, encoding: "utf-16le" };
        start = -1;
        characters = "";
      }
    }
  }
}

const excerptOf = (text: string, index: number, length: number): string => {
  const from = Math.max(0, index - EXCERPT_CONTEXT);
  const to = Math.min(text.length, index + length + EXCERPT_CONTEXT);
  return `${from > 0 ? "…" : ""}${text.slice(from, to)}${to < text.length ? "…" : ""}`;
};

/** One analyst-directed match inside a string, by UTF-16 code-unit index. */
export interface AnalystDirectedTextMatch {
  readonly index: number;
  readonly length: number;
  readonly category: Category;
  readonly rule: string;
  readonly excerpt: string;
}

/** Yield every analyst-directed match in one string, in order. */
export function* matchAnalystDirectedText(
  text: string,
): Generator<AnalystDirectedTextMatch> {
  for (const match of text.matchAll(COMBINED)) {
    const ruleIndex = Object.values(match.groups ?? {}).findIndex(
      (value) => value !== undefined,
    );
    const rule = RULES[ruleIndex];
    if (rule === undefined) continue;
    yield {
      index: match.index,
      length: match[0].length,
      category: rule.category,
      rule: rule.id,
      excerpt: excerptOf(text, match.index, match[0].length),
    };
  }
}

/**
 * Report target-controlled text that appears to address an AI analyst:
 * chat-template tokens, instruction overrides, role assignments, requests to
 * stop analysis, benign-verdict assertions and tool-call markup. Findings
 * carry file offsets so a caller can confirm them; the text is never treated
 * as an instruction.
 */
export const scanAnalystDirectedText = (
  bytes: Uint8Array,
  options: {
    readonly minimumLength: number;
    readonly maximumFindings: number;
    readonly signal?: AbortSignal;
  },
): AnalystDirectedTextScan => {
  const findings: AnalystDirectedTextFinding[] = [];
  let scanned = 0;
  let truncated = false;
  const runs = function* () {
    yield* asciiRuns(bytes, options.minimumLength);
    yield* utf16Runs(bytes, options.minimumLength);
  };
  for (const run of runs()) {
    scanned++;
    if (scanned % CANCEL_CHECK_INTERVAL === 0) options.signal?.throwIfAborted();
    for (const match of matchAnalystDirectedText(run.text)) {
      if (findings.length === options.maximumFindings) {
        truncated = true;
        break;
      }
      const width = run.encoding === "utf-16le" ? 2 : 1;
      findings.push({
        location: {
          offset: run.offset + match.index * width,
          bytes: match.length * width,
        },
        encoding: run.encoding,
        category: match.category,
        rule: match.rule,
        excerpt: match.excerpt,
      });
    }
  }
  findings.sort(
    (left, right) =>
      left.location.offset - right.location.offset ||
      left.rule.localeCompare(right.rule),
  );
  return { findings, scanned_strings: scanned, truncated };
};

/** Analyst-directed text found inside a structured tool result. */
export interface JsonAnalystDirectedTextFinding {
  /** RFC 6901 JSON Pointer to the string value that contains the match. */
  readonly pointer: string;
  readonly category: Category;
  readonly rule: string;
  readonly excerpt: string;
}

export interface JsonAnalystDirectedTextScan {
  readonly findings: JsonAnalystDirectedTextFinding[];
  readonly truncated: boolean;
}

const pointerToken = (token: string | number): string =>
  String(token).replaceAll("~", "~0").replaceAll("/", "~1");

/**
 * Scan every string value of a JSON result for analyst-directed text. The
 * walk is iterative, skips object keys and short strings, and stops at the
 * finding or character budget, reporting truncation.
 */
export const scanJsonForAnalystDirectedText = (
  value: unknown,
  limits: {
    readonly maximumFindings: number;
    readonly maximumCharacters: number;
    readonly minimumLength?: number;
  },
): JsonAnalystDirectedTextScan => {
  const minimum = limits.minimumLength ?? 6;
  const findings: JsonAnalystDirectedTextFinding[] = [];
  let characters = 0;
  const stack: [unknown, string][] = [[value, ""]];
  while (stack.length > 0) {
    const [item, pointer] = stack.pop()!;
    if (typeof item === "string") {
      if (item.length < minimum) continue;
      characters += item.length;
      if (characters > limits.maximumCharacters)
        return { findings, truncated: true };
      for (const match of matchAnalystDirectedText(item)) {
        if (findings.length === limits.maximumFindings)
          return { findings, truncated: true };
        findings.push({
          pointer,
          category: match.category,
          rule: match.rule,
          excerpt: match.excerpt,
        });
      }
    } else if (Array.isArray(item)) {
      for (let index = item.length - 1; index >= 0; index--)
        stack.push([item[index], `${pointer}/${index}`]);
    } else if (typeof item === "object" && item !== null) {
      const entries = Object.entries(item);
      for (let index = entries.length - 1; index >= 0; index--) {
        const [key, child] = entries[index]!;
        stack.push([child, `${pointer}/${pointerToken(key)}`]);
      }
    }
  }
  return { findings, truncated: false };
};
