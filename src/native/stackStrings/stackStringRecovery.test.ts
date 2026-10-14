import { expect, it } from "vitest";
import {
  decodeStackEvent,
  recoverStackStrings,
} from "./stackStringRecovery.js";

const code = (...parts: (number[] | Buffer)[]) =>
  Buffer.concat(
    parts.map((part) => (Buffer.isBuffer(part) ? part : Buffer.from(part))),
  );
const region = (bytes: Buffer) => [
  { name: ".text", offset: 0, bytes: bytes.length },
];
const recover = (bytes: Buffer, mode: 32 | 64 = 64, minimumLength = 6) =>
  recoverStackStrings(bytes, region(bytes), { mode, minimumLength }).map(
    ({ string }) => string,
  );

/** mov byte [rbp+disp8], imm8 for each character, then the terminator. */
const perByte = (text: string, start = -0x20) =>
  [...`${text}\0`].map((char, index) => [
    0xc6,
    0x45,
    (start + index) & 0xff,
    char.charCodeAt(0),
  ]);
const ret = [0xc3];

it("recovers per-byte stores relative to rbp", () => {
  expect(recover(code(...perByte("GetProcAddress"), ret))).toEqual([
    "GetProcAddress",
  ]);
});

it("recovers dword stores through an rsp SIB operand", () => {
  // mov dword [rsp+0x10+4k], imm32 for "LoadLibraryA\0\0\0\0"
  const words = ["Load", "Libr", "aryA", "\0\0\0\0"];
  const stores = words.map((word, index) => [
    0xc7,
    0x44,
    0x24,
    0x10 + 4 * index,
    ...Buffer.from(word, "latin1"),
  ]);
  expect(recover(code(...stores, ret))).toEqual(["LoadLibraryA"]);
});

it("tracks movabs immediates through registers, with overlapping tail stores", () => {
  // movabs rax, "kernel32"; mov [rsp+3], rax; lea rdi,[rsp+3]; movabs rax, "l32.dll\0"; mov [rsp+8], rax
  const bytes = code(
    [0x48, 0xb8],
    Buffer.from("kernel32", "latin1"),
    [0x48, 0x89, 0x44, 0x24, 0x03],
    [0x48, 0x8d, 0x7c, 0x24, 0x03],
    [0x48, 0xb8],
    Buffer.from("l32.dll\0", "latin1"),
    [0x48, 0x89, 0x44, 0x24, 0x08],
    ret,
  );
  expect(recover(bytes)).toEqual(["kernel32.dll"]);
});

it("recovers UTF-16LE stack strings built from word stores", () => {
  const stores = [..."cmd.exe\0"].map((char, index) => [
    0x66,
    0xc7,
    0x45,
    (0xe0 + 2 * index) & 0xff,
    char.charCodeAt(0),
    0,
  ]);
  const found = recoverStackStrings(
    code(...stores, ret),
    region(code(...stores, ret)),
    { mode: 64, minimumLength: 6 },
  );
  expect(found).toEqual([
    expect.objectContaining({
      string: "cmd.exe",
      encoding: "utf-16le",
      base_register: "rbp",
    }),
  ]);
});

it("decodes 32-bit code without REX prefixes", () => {
  // In 32-bit mode 0x48 is dec eax, so a REX-looking byte must not be consumed.
  expect(
    decodeStackEvent(Buffer.from([0x48, 0xc6, 0x45, 0xf0, 0x41]), 0, 32),
  ).toBeNull();
  expect(recover(code(...perByte("WinExecute"), ret), 32)).toEqual([
    "WinExecute",
  ]);
});

it("keeps strings from neighbouring functions apart", () => {
  const bytes = code(
    ...perByte("FirstString"),
    ret,
    [0xcc, 0xcc],
    ...perByte("SecondThing"),
    ret,
  );
  expect(recover(bytes)).toEqual(["FirstString", "SecondThing"]);
});

it("reports each string a reused buffer held", () => {
  const bytes = code(
    ...perByte("alphastring"),
    [0x90],
    ...perByte("bravostring"),
    ret,
  );
  expect(recover(bytes).sort()).toEqual(["alphastring", "bravostring"]);
});

it("ignores immediates that are not plausible text and short fragments", () => {
  // Same character repeated, and a two-store four-letter word, are rejected.
  const repeated = code(...perByte("AAAAAAAAAA"), ret);
  expect(recover(repeated)).toEqual([]);
  expect(recover(code(...perByte("abcd"), ret))).toEqual([]);
});

it("returns instruction offsets that point at the stores", () => {
  const prefix = Buffer.from([0x55, 0x48, 0x89, 0xe5]); // push rbp; mov rbp, rsp
  const bytes = code(prefix, ...perByte("VirtualAlloc"), ret);
  const [found] = recoverStackStrings(bytes, region(bytes), {
    mode: 64,
    minimumLength: 6,
  });
  expect(found).toMatchObject({
    first_instruction_offset: 4,
    frame_offset: -0x20,
    stores: 12,
  });
  expect(bytes[found!.first_instruction_offset]).toBe(0xc6);
});
