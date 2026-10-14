/**
 * Recover strings that a program assembles on the stack with immediate
 * stores, such as `mov byte [rbp-0x10], 'k'` or `movabs rax, imm64` followed
 * by `mov [rsp+8], rax`. Plain string extraction misses these because the
 * characters live inside instruction immediates.
 *
 * The scan decodes only the instruction forms that store immediates or load
 * registers with immediates, at every byte offset of executable code. Nearby
 * events form a group; each group is replayed into a per-base-register byte
 * map, and printable runs in that map become candidate strings. Nothing is
 * executed or emulated.
 */

export type StackStringMode = 32 | 64;

export interface StackStringRegion {
  readonly name: string;
  readonly offset: number;
  readonly bytes: number;
}

export interface RecoveredStackString {
  readonly string: string;
  readonly encoding: "ascii" | "utf-16le";
  readonly section: string;
  /** File offset of the first and last instruction that wrote the string. */
  readonly first_instruction_offset: number;
  readonly last_instruction_offset: number;
  readonly base_register: string;
  readonly frame_offset: number;
  readonly stores: number;
}

type Event =
  | {
      readonly kind: "load";
      readonly offset: number;
      readonly length: number;
      readonly register: number;
      readonly value: bigint;
      readonly width: number;
    }
  | {
      readonly kind: "store";
      readonly offset: number;
      readonly length: number;
      readonly base: number;
      readonly displacement: number;
      readonly width: number;
      readonly value: bigint | null;
      readonly register: number | null;
    };

// Compilers interleave a few unrelated instructions (lea, sub, call setup)
// between the stores that build one string.
const MAX_GAP_BYTES = 32;
const REGISTERS_64 = [
  "rax",
  "rcx",
  "rdx",
  "rbx",
  "rsp",
  "rbp",
  "rsi",
  "rdi",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
];
const REGISTERS_32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];

const signed8 = (value: number) => (value << 24) >> 24;

interface MemoryOperand {
  readonly base: number;
  readonly displacement: number;
  readonly length: number;
  readonly register: number;
}

/** Decode a ModRM memory operand with no index register and a register base. */
const memoryOperand = (
  bytes: Uint8Array,
  at: number,
  rexB: number,
  rexR: number,
  rexX: number,
): MemoryOperand | null => {
  const modrm = bytes[at];
  if (modrm === undefined) return null;
  const mod = modrm >> 6;
  const register = ((modrm >> 3) & 7) | rexR;
  let rm = modrm & 7;
  let cursor = at + 1;
  if (mod === 3) return null;
  let base: number;
  if (rm === 4) {
    const sib = bytes[cursor];
    if (sib === undefined) return null;
    cursor++;
    const index = ((sib >> 3) & 7) | rexX;
    if (index !== 4) return null;
    rm = sib & 7;
    if (rm === 5 && mod === 0) return null;
    base = rm | rexB;
  } else {
    if (rm === 5 && mod === 0) return null;
    base = rm | rexB;
  }
  let displacement = 0;
  if (mod === 1) {
    const value = bytes[cursor];
    if (value === undefined) return null;
    displacement = signed8(value);
    cursor += 1;
  } else if (mod === 2) {
    if (cursor + 4 > bytes.length) return null;
    displacement = new DataView(
      bytes.buffer,
      bytes.byteOffset + cursor,
      4,
    ).getInt32(0, true);
    cursor += 4;
  }
  return { base, displacement, length: cursor - at, register };
};

const readLittle = (
  bytes: Uint8Array,
  at: number,
  width: number,
): bigint | null => {
  if (at + width > bytes.length) return null;
  let value = 0n;
  for (let index = width - 1; index >= 0; index--)
    value = (value << 8n) | BigInt(bytes[at + index]!);
  return value;
};

/** Decode one store-immediate, store-register or load-immediate instruction. */
export const decodeStackEvent = (
  bytes: Uint8Array,
  at: number,
  mode: StackStringMode,
): Event | null => {
  let cursor = at;
  let operandSize16 = false;
  if (bytes[cursor] === 0x66) {
    operandSize16 = true;
    cursor++;
  }
  let rexW = false;
  let rexR = 0;
  let rexX = 0;
  let rexB = 0;
  let rex = false;
  const prefix = bytes[cursor];
  if (mode === 64 && prefix !== undefined && prefix >= 0x40 && prefix <= 0x4f) {
    rex = true;
    rexW = (prefix & 8) !== 0;
    rexR = (prefix & 4) << 1;
    rexX = (prefix & 2) << 2;
    rexB = (prefix & 1) << 3;
    cursor++;
  }
  const opcode = bytes[cursor];
  if (opcode === undefined) return null;
  cursor++;

  // mov r/m8, imm8 and mov r/m16/32/64, imm16/32
  if (opcode === 0xc6 || opcode === 0xc7) {
    const operand = memoryOperand(bytes, cursor, rexB, rexR, rexX);
    if (operand === null || (operand.register & 7) !== 0) return null;
    cursor += operand.length;
    const immediateWidth = opcode === 0xc6 ? 1 : operandSize16 ? 2 : 4;
    const storeWidth = opcode === 0xc6 ? 1 : operandSize16 ? 2 : rexW ? 8 : 4;
    const raw = readLittle(bytes, cursor, immediateWidth);
    if (raw === null) return null;
    cursor += immediateWidth;
    // A 64-bit store sign-extends its 32-bit immediate.
    const value =
      storeWidth === 8 && (raw & 0x80000000n) !== 0n
        ? raw | 0xffffffff00000000n
        : raw;
    return {
      kind: "store",
      offset: at,
      length: cursor - at,
      base: operand.base,
      displacement: operand.displacement,
      width: storeWidth,
      value,
      register: null,
    };
  }
  // mov r/m8, r8 and mov r/m16/32/64, r16/32/64
  if (opcode === 0x88 || opcode === 0x89) {
    const operand = memoryOperand(bytes, cursor, rexB, rexR, rexX);
    if (operand === null) return null;
    cursor += operand.length;
    if (opcode === 0x88 && !rex && operand.register >= 4) return null; // ah..bh
    return {
      kind: "store",
      offset: at,
      length: cursor - at,
      base: operand.base,
      displacement: operand.displacement,
      width: opcode === 0x88 ? 1 : operandSize16 ? 2 : rexW ? 8 : 4,
      value: null,
      register: operand.register,
    };
  }
  // mov r8, imm8
  if (opcode >= 0xb0 && opcode <= 0xb7) {
    const register = (opcode - 0xb0) | rexB;
    if (!rex && register >= 4) return null;
    const value = readLittle(bytes, cursor, 1);
    if (value === null) return null;
    return {
      kind: "load",
      offset: at,
      length: cursor + 1 - at,
      register,
      value,
      width: 1,
    };
  }
  // mov r16/32, imm16/32 and movabs r64, imm64
  if (opcode >= 0xb8 && opcode <= 0xbf) {
    const register = (opcode - 0xb8) | rexB;
    const width = rexW ? 8 : operandSize16 ? 2 : 4;
    const value = readLittle(bytes, cursor, width);
    if (value === null) return null;
    return {
      kind: "load",
      offset: at,
      length: cursor + width - at,
      register,
      value,
      width,
    };
  }
  return null;
};

const MASK = (width: number) => (1n << BigInt(width * 8)) - 1n;

const printableAscii = (byte: number) => byte >= 0x20 && byte <= 0x7e;

const plausible = (text: string) =>
  new Set(text).size >= 3 && /[A-Za-z]/.test(text);

/** Replay one group of events and extract printable strings per base register. */
const groupStrings = (
  events: readonly Event[],
  section: string,
  mode: StackStringMode,
  minimumLength: number,
): RecoveredStackString[] => {
  const registers = new Map<number, bigint>();
  const memory = new Map<number, Frame>();
  const names = mode === 64 ? REGISTERS_64 : REGISTERS_32;
  const found: RecoveredStackString[] = [];
  for (const event of events) {
    if (event.kind === "load") {
      const previous = registers.get(event.register) ?? 0n;
      // 32-bit writes zero-extend; 8- and 16-bit writes keep the upper bits.
      registers.set(
        event.register,
        event.width >= 4
          ? event.value
          : (previous & ~MASK(event.width)) | event.value,
      );
      continue;
    }
    const value =
      event.value ??
      (event.register === null ? undefined : registers.get(event.register));
    if (value === undefined) continue;
    let frame = memory.get(event.base) ?? new Map();
    // A buffer reused for a second string: keep what the first one held.
    // Compilers also write overlapping stores whose shared bytes agree; those
    // continue the same string.
    for (let index = 0; index < event.width; index++)
      if (
        frame.has(event.displacement + index) &&
        frame.get(event.displacement + index)!.byte !==
          Number((value >> BigInt(index * 8)) & 0xffn)
      ) {
        found.push(
          ...frameStrings(
            frame,
            section,
            names[event.base] ?? `r${event.base}`,
            minimumLength,
          ),
        );
        frame = new Map();
        break;
      }
    memory.set(event.base, frame);
    for (let index = 0; index < event.width; index++)
      frame.set(event.displacement + index, {
        byte: Number((value >> BigInt(index * 8)) & 0xffn),
        event,
      });
  }
  for (const [base, frame] of memory)
    found.push(
      ...frameStrings(frame, section, names[base] ?? `r${base}`, minimumLength),
    );
  return found;
};

type Frame = Map<number, { byte: number; event: Event }>;

/** Split one register's byte map into contiguous runs and extract their strings. */
const frameStrings = (
  frame: Frame,
  section: string,
  register: string,
  minimumLength: number,
): RecoveredStackString[] => {
  const found: RecoveredStackString[] = [];
  const offsets = [...frame.keys()].sort((left, right) => left - right);
  let start = 0;
  while (start < offsets.length) {
    let end = start;
    while (end + 1 < offsets.length && offsets[end + 1] === offsets[end]! + 1)
      end++;
    const run = offsets
      .slice(start, end + 1)
      .map((offset) => ({ offset, ...frame.get(offset)! }));
    found.push(...stringsInRun(run, section, register, minimumLength));
    start = end + 1;
  }
  return found;
};

const stringsInRun = (
  run: readonly { offset: number; byte: number; event: Event }[],
  section: string,
  register: string,
  minimumLength: number,
): RecoveredStackString[] => {
  const results: RecoveredStackString[] = [];
  const emit = (
    slice: typeof run,
    text: string,
    encoding: "ascii" | "utf-16le",
  ) => {
    const events = new Set(slice.map(({ event }) => event));
    if (events.size < 2 && text.length < 8) return;
    if (!plausible(text)) return;
    const offsets = [...events].map(({ offset }) => offset);
    results.push({
      string: text,
      encoding,
      section,
      first_instruction_offset: Math.min(...offsets),
      last_instruction_offset: Math.max(...offsets),
      base_register: register,
      frame_offset: slice[0]!.offset,
      stores: [...events].filter(({ kind }) => kind === "store").length,
    });
  };
  // UTF-16LE: printable byte followed by zero, repeated.
  let index = 0;
  while (index < run.length) {
    let cursor = index;
    let text = "";
    while (
      cursor + 1 < run.length &&
      printableAscii(run[cursor]!.byte) &&
      run[cursor + 1]!.byte === 0
    ) {
      text += String.fromCharCode(run[cursor]!.byte);
      cursor += 2;
    }
    if (text.length >= minimumLength) {
      emit(run.slice(index, cursor), text, "utf-16le");
      index = cursor;
      continue;
    }
    cursor = index;
    text = "";
    while (cursor < run.length && printableAscii(run[cursor]!.byte)) {
      text += String.fromCharCode(run[cursor]!.byte);
      cursor++;
    }
    if (text.length >= minimumLength)
      emit(run.slice(index, cursor), text, "ascii");
    index = Math.max(cursor, index + 1);
  }
  return results;
};

const boundaryAt = (bytes: Uint8Array, at: number): boolean => {
  const byte = bytes[at];
  return (
    byte === 0xc3 ||
    byte === 0xcc ||
    (byte === 0xf3 &&
      bytes[at + 1] === 0x0f &&
      bytes[at + 2] === 0x1e &&
      (bytes[at + 3] === 0xfa || bytes[at + 3] === 0xfb))
  );
};

/** Scan executable regions for stack-built strings. */
export const recoverStackStrings = (
  bytes: Uint8Array,
  regions: readonly StackStringRegion[],
  options: {
    readonly mode: StackStringMode;
    readonly minimumLength: number;
    readonly signal?: AbortSignal;
  },
): RecoveredStackString[] => {
  const results: RecoveredStackString[] = [];
  for (const region of regions) {
    const end = Math.min(bytes.length, region.offset + region.bytes);
    let group: Event[] = [];
    let groupEnd = -1;
    const flush = () => {
      if (group.filter(({ kind }) => kind === "store").length > 0)
        results.push(
          ...groupStrings(
            group,
            region.name,
            options.mode,
            options.minimumLength,
          ),
        );
      group = [];
    };
    for (let at = region.offset; at < end;) {
      if ((at & 0xffff) === 0) options.signal?.throwIfAborted();
      const event = decodeStackEvent(bytes.subarray(0, end), at, options.mode);
      if (event === null) {
        // ret, int3 padding and endbr64 mark function boundaries; frames on
        // either side reuse the same offsets and must not be merged.
        if (boundaryAt(bytes, at)) flush();
        at++;
        continue;
      }
      if (group.length > 0 && event.offset - groupEnd > MAX_GAP_BYTES) flush();
      group.push(event);
      groupEnd = event.offset + event.length;
      at += event.length;
    }
    flush();
  }
  // The same string can be rebuilt in several functions; keep each site.
  return results.sort(
    (left, right) =>
      left.first_instruction_offset - right.first_instruction_offset ||
      left.string.localeCompare(right.string),
  );
};
