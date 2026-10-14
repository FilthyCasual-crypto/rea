import { randomBytes } from "node:crypto";
import { expect, it } from "vitest";
import {
  detectTriageFormat,
  entropyProfile,
  measureSections,
  packerIndicators,
  parseTriageSections,
  shannonEntropy,
} from "./binaryTriageAnalysis.js";

/** Minimal ELF64 little-endian image with .text, .data and .shstrtab. */
const elf64 = (options: { stripSections?: boolean } = {}) => {
  const text = Buffer.alloc(256, 0x90);
  const data = Buffer.from("hello world\0", "latin1");
  const names = Buffer.from("\0.text\0.data\0.shstrtab\0", "latin1");
  const textOffset = 0x40 + 0x38;
  const dataOffset = textOffset + text.length;
  const namesOffset = dataOffset + data.length;
  const shoff = namesOffset + names.length;
  const header = Buffer.alloc(0x40);
  header.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  header.writeUInt16LE(2, 0x10);
  header.writeUInt16LE(0x3e, 0x12);
  header.writeBigUInt64LE(0x40n, 0x20); // e_phoff
  header.writeBigUInt64LE(BigInt(options.stripSections ? 0 : shoff), 0x28);
  header.writeUInt16LE(0x38, 0x36);
  header.writeUInt16LE(1, 0x38); // one program header
  header.writeUInt16LE(0x40, 0x3a);
  header.writeUInt16LE(options.stripSections ? 0 : 4, 0x3c);
  header.writeUInt16LE(3, 0x3e);
  const program = Buffer.alloc(0x38);
  program.writeUInt32LE(1, 0); // PT_LOAD
  program.writeUInt32LE(5, 4); // R+X
  program.writeBigUInt64LE(BigInt(textOffset), 8);
  program.writeBigUInt64LE(BigInt(text.length), 0x20);
  const section = (
    name: number,
    type: number,
    flags: number,
    offset: number,
    size: number,
  ) => {
    const entry = Buffer.alloc(0x40);
    entry.writeUInt32LE(name, 0);
    entry.writeUInt32LE(type, 4);
    entry.writeBigUInt64LE(BigInt(flags), 8);
    entry.writeBigUInt64LE(BigInt(offset), 0x18);
    entry.writeBigUInt64LE(BigInt(size), 0x20);
    return entry;
  };
  return Buffer.concat([
    header,
    program,
    text,
    data,
    names,
    section(0, 0, 0, 0, 0),
    section(1, 1, 0x6, textOffset, text.length),
    section(7, 1, 0x3, dataOffset, data.length),
    section(13, 3, 0, namesOffset, names.length),
  ]);
};

/** Minimal PE32+ image with two UPX-named sections and no imports. */
const upxPe = () => {
  const bytes = Buffer.alloc(0x400 + 0x1000 + 0x2000);
  bytes.write("MZ", 0, "latin1");
  bytes.writeUInt32LE(0x80, 0x3c);
  bytes.write("PE\0\0", 0x80, "latin1");
  bytes.writeUInt16LE(0x8664, 0x84);
  bytes.writeUInt16LE(2, 0x86);
  bytes.writeUInt16LE(240, 0x94);
  const optional = 0x98;
  bytes.writeUInt16LE(0x20b, optional);
  const table = optional + 240;
  const section = (
    index: number,
    name: string,
    offset: number,
    size: number,
    characteristics: number,
  ) => {
    const base = table + index * 40;
    bytes.write(name, base, "latin1");
    bytes.writeUInt32LE(size, base + 8);
    bytes.writeUInt32LE(0x1000 * (index + 1), base + 12);
    bytes.writeUInt32LE(size, base + 16);
    bytes.writeUInt32LE(offset, base + 20);
    bytes.writeUInt32LE(characteristics, base + 36);
  };
  section(0, "UPX0", 0x400, 0x1000, 0xe0000080);
  section(1, "UPX1", 0x1400, 0x2000, 0x60000040);
  randomBytes(0x2000).copy(bytes, 0x1400);
  bytes.write("UPX!", 0x3e0, "latin1");
  return bytes;
};

it("measures Shannon entropy at both extremes", () => {
  expect(shannonEntropy(Buffer.alloc(1024))).toBe(0);
  expect(
    shannonEntropy(Buffer.from(Array.from({ length: 256 }, (_, i) => i))),
  ).toBe(8);
  const profile = entropyProfile(Buffer.alloc(10000));
  expect(profile).toMatchObject({ windows: 3, high_entropy_windows: 0 });
});

it.each([
  [Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]), "elf"],
  [Buffer.from("MZ\0\0", "latin1"), "dos-mz"],
  [Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), "mach-o"],
  [Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]), "mach-o-universal"],
  [Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]), "java-class"],
  [Buffer.from("dex\n035\0", "latin1"), "dex"],
  [Buffer.from([0x50, 0x4b, 0x03, 0x04]), "zip"],
  [Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), "wasm"],
  [Buffer.from("plain text", "latin1"), "unknown"],
] as const)("detects %s as %s", (bytes, format) => {
  expect(detectTriageFormat(bytes)).toBe(format);
});

it("reads ELF64 sections with flags and skips empty or non-file sections", () => {
  const bytes = elf64();
  expect(detectTriageFormat(bytes)).toBe("elf");
  const parsed = parseTriageSections(bytes, "elf");
  expect(parsed.coverage).toBe("complete");
  const { sections } = measureSections(bytes, parsed);
  expect(
    sections.map(({ name, executable, writable }) => ({
      name,
      executable,
      writable,
    })),
  ).toEqual([
    { name: ".text", executable: true, writable: false },
    { name: ".data", executable: false, writable: true },
    { name: ".shstrtab", executable: false, writable: false },
  ]);
  expect(sections[0]!.entropy).toBe(0);
});

it("falls back to PT_LOAD segments when ELF section headers are stripped", () => {
  const bytes = elf64({ stripSections: true });
  const parsed = parseTriageSections(bytes, "elf");
  expect(parsed.sections).toEqual([
    expect.objectContaining({
      name: "PT_LOAD[0]",
      executable: true,
      writable: false,
    }),
  ]);
  expect(parsed.limitations.join(" ")).toMatch(/program segments/);
});

it("identifies UPX-packed PE images from observed facts and labelled heuristics", () => {
  const bytes = upxPe();
  expect(detectTriageFormat(bytes)).toBe("pe");
  const parsed = parseTriageSections(bytes, "pe");
  expect(parsed.peImportDescriptors).toBe(0);
  const { sections } = measureSections(bytes, parsed);
  const indicators = packerIndicators(
    bytes,
    "pe",
    sections,
    parsed,
    shannonEntropy(bytes),
  );
  const ids = indicators.map((indicator) => indicator.id);
  expect(ids).toEqual(
    expect.arrayContaining([
      "upx-marker",
      "section-name:UPX0",
      "section-name:UPX1",
      "high-entropy-executable:UPX1",
      "writable-executable:UPX0",
      "sparse-imports-high-entropy",
    ]),
  );
  for (const indicator of indicators)
    expect(indicator.confidence).toBe(
      indicator.kind === "heuristic" ? "inferred" : "observed",
    );
});

it("clamps sections that extend past the file and records why", () => {
  const bytes = upxPe().subarray(0, 0x2000);
  const parsed = parseTriageSections(bytes, "pe");
  const measured = measureSections(bytes, parsed);
  expect(
    measured.sections[1]!.location.offset +
      measured.sections[1]!.location.bytes,
  ).toBe(0x2000);
  expect(measured.limitations.join(" ")).toMatch(/only/);
});

it("reports no sections for formats without a section table", () => {
  expect(
    parseTriageSections(Buffer.from("dex\n", "latin1"), "dex"),
  ).toMatchObject({
    sections: [],
    coverage: "not_applicable",
  });
  expect(
    parseTriageSections(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]), "elf")
      .coverage,
  ).toBe("unparsed");
});
