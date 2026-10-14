import type {
  PackerIndicator,
  TriageFormat,
  TriageSection,
} from "../../domain/native/binaryTriage.js";

export const ENTROPY_WINDOW_BYTES = 4096;
export const HIGH_ENTROPY_THRESHOLD = 7.2;
const MAX_SECTIONS = 4096;
const MAX_IMPORT_DESCRIPTORS = 4096;

/** Shannon entropy of a byte range in bits per byte, rounded to four decimals. */
export const shannonEntropy = (bytes: Uint8Array): number => {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte]!++;
  let total = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / bytes.length;
    total -= probability * Math.log2(probability);
  }
  return Math.round(total * 10000) / 10000;
};

export const entropyProfile = (bytes: Uint8Array) => {
  let windows = 0;
  let high = 0;
  for (let offset = 0; offset < bytes.length; offset += ENTROPY_WINDOW_BYTES) {
    windows++;
    if (
      shannonEntropy(bytes.subarray(offset, offset + ENTROPY_WINDOW_BYTES)) >=
      HIGH_ENTROPY_THRESHOLD
    )
      high++;
  }
  return {
    whole_file: shannonEntropy(bytes),
    window_bytes: ENTROPY_WINDOW_BYTES,
    windows,
    high_entropy_windows: high,
    high_entropy_threshold: HIGH_ENTROPY_THRESHOLD,
  };
};

const view = (bytes: Uint8Array) =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

const startsWith = (bytes: Uint8Array, prefix: readonly number[]) =>
  prefix.every((value, index) => bytes[index] === value);

const peHeaderOffset = (bytes: Uint8Array): number | null => {
  if (bytes.length < 0x40) return null;
  const offset = view(bytes).getUint32(0x3c, true);
  return offset + 24 <= bytes.length &&
    startsWith(bytes.subarray(offset), [0x50, 0x45, 0, 0])
    ? offset
    : null;
};

/** Identify the container from its magic bytes only. */
export const detectTriageFormat = (bytes: Uint8Array): TriageFormat => {
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) return "elf";
  if (startsWith(bytes, [0x4d, 0x5a]))
    return peHeaderOffset(bytes) === null ? "dos-mz" : "pe";
  if (bytes.length >= 4) {
    const magic = view(bytes).getUint32(0, false);
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magic))
      return "mach-o";
    if (magic === 0xcafebabe || magic === 0xcafebabf) {
      // Java class files share the magic; their minor/major version word is
      // at least 45, while universal headers carry a small architecture count.
      if (bytes.length < 8) return "unknown";
      return view(bytes).getUint32(4, false) < 45
        ? "mach-o-universal"
        : "java-class";
    }
  }
  if (startsWith(bytes, [0x64, 0x65, 0x78, 0x0a])) return "dex";
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04])) return "zip";
  if (startsWith(bytes, [0x00, 0x61, 0x73, 0x6d])) return "wasm";
  return "unknown";
};

interface RawSection {
  readonly name: string;
  readonly offset: number;
  readonly size: number;
  readonly executable: boolean | null;
  readonly writable: boolean | null;
}

export interface SectionParse {
  readonly sections: RawSection[];
  readonly coverage: "complete" | "not_applicable" | "unparsed";
  readonly limitations: string[];
  readonly peImportDescriptors: number | null;
  readonly peManaged: boolean;
}

const cString = (bytes: Uint8Array, offset: number, maximum: number) => {
  let end = offset;
  while (end < bytes.length && end - offset < maximum && bytes[end] !== 0)
    end++;
  return Buffer.from(bytes.subarray(offset, end)).toString("latin1");
};

const parseElfSections = (bytes: Uint8Array): SectionParse => {
  const failed = (reason: string): SectionParse => ({
    sections: [],
    coverage: "unparsed",
    limitations: [reason],
    peImportDescriptors: null,
    peManaged: false,
  });
  if (bytes.length < 0x34) return failed("ELF header is truncated.");
  const wide = bytes[4] === 2;
  const little = bytes[5] === 1;
  if (![1, 2].includes(bytes[4]!) || ![1, 2].includes(bytes[5]!))
    return failed("ELF class or data encoding is not recognized.");
  const data = view(bytes);
  const u16 = (offset: number) => data.getUint16(offset, little);
  const u32 = (offset: number) => data.getUint32(offset, little);
  const word = (offset: number) =>
    wide ? Number(data.getBigUint64(offset, little)) : u32(offset);
  if (bytes.length < (wide ? 0x40 : 0x34))
    return failed("ELF header is truncated.");
  const shoff = word(wide ? 0x28 : 0x20);
  const shentsize = u16(wide ? 0x3a : 0x2e);
  const shnum = u16(wide ? 0x3c : 0x30);
  const shstrndx = u16(wide ? 0x3e : 0x32);
  const sections: RawSection[] = [];
  const limitations: string[] = [];
  const tableFits =
    shnum > 0 &&
    shnum <= MAX_SECTIONS &&
    shentsize >= (wide ? 0x40 : 0x28) &&
    shoff + shnum * shentsize <= bytes.length;
  if (tableFits) {
    const header = (index: number) => shoff + index * shentsize;
    const stringTable =
      shstrndx < shnum ? word(header(shstrndx) + (wide ? 0x18 : 0x10)) : null;
    for (let index = 0; index < shnum; index++) {
      const base = header(index);
      const type = u32(base + 4);
      const flags = wide
        ? Number(data.getBigUint64(base + 8, little))
        : u32(base + 8);
      const offset = word(base + (wide ? 0x18 : 0x10));
      const size = word(base + (wide ? 0x20 : 0x14));
      // SHT_NULL and SHT_NOBITS occupy no file bytes.
      if (type === 0 || type === 8 || size === 0) continue;
      const nameOffset = u32(base);
      const name =
        stringTable !== null && stringTable + nameOffset < bytes.length
          ? cString(bytes, stringTable + nameOffset, 256)
          : `section[${index}]`;
      sections.push({
        name,
        offset,
        size,
        executable: (flags & 0x4) !== 0,
        writable: (flags & 0x1) !== 0,
      });
    }
    return {
      sections,
      coverage: "complete",
      limitations,
      peImportDescriptors: null,
      peManaged: false,
    };
  }
  // Stripped section headers: fall back to loadable program segments.
  const phoff = word(wide ? 0x20 : 0x1c);
  const phentsize = u16(wide ? 0x36 : 0x2a);
  const phnum = u16(wide ? 0x38 : 0x2c);
  if (
    phnum === 0 ||
    phnum > MAX_SECTIONS ||
    phentsize < (wide ? 0x38 : 0x20) ||
    phoff + phnum * phentsize > bytes.length
  )
    return failed(
      "ELF section and program header tables are absent or out of range.",
    );
  for (let index = 0; index < phnum; index++) {
    const base = phoff + index * phentsize;
    if (u32(base) !== 1) continue; // PT_LOAD
    const flags = u32(base + (wide ? 4 : 0x18));
    const offset = word(base + (wide ? 8 : 4));
    const size = word(base + (wide ? 0x20 : 0x10));
    if (size === 0) continue;
    sections.push({
      name: `PT_LOAD[${index}]`,
      offset,
      size,
      executable: (flags & 0x1) !== 0,
      writable: (flags & 0x2) !== 0,
    });
  }
  limitations.push(
    "ELF section headers are absent or invalid; loadable program segments are reported instead.",
  );
  return {
    sections,
    coverage: "complete",
    limitations,
    peImportDescriptors: null,
    peManaged: false,
  };
};

const parsePeSections = (bytes: Uint8Array): SectionParse => {
  const pe = peHeaderOffset(bytes)!;
  const data = view(bytes);
  const count = data.getUint16(pe + 6, true);
  const optionalSize = data.getUint16(pe + 20, true);
  const optional = pe + 24;
  const table = optional + optionalSize;
  const limitations: string[] = [];
  if (count > MAX_SECTIONS || table + count * 40 > bytes.length)
    return {
      sections: [],
      coverage: "unparsed",
      limitations: ["PE section table is out of range."],
      peImportDescriptors: null,
      peManaged: false,
    };
  const sections: (RawSection & { rva: number; virtualSize: number })[] = [];
  for (let index = 0; index < count; index++) {
    const base = table + index * 40;
    const characteristics = data.getUint32(base + 36, true);
    sections.push({
      name: cString(bytes, base, 8),
      virtualSize: data.getUint32(base + 8, true),
      rva: data.getUint32(base + 12, true),
      size: data.getUint32(base + 16, true),
      offset: data.getUint32(base + 20, true),
      executable: (characteristics & 0x20000000) !== 0,
      writable: (characteristics & 0x80000000) !== 0,
    });
  }
  const magic =
    optionalSize >= 2 && optional + 2 <= bytes.length
      ? data.getUint16(optional, true)
      : 0;
  const directories =
    magic === 0x10b ? optional + 96 : magic === 0x20b ? optional + 112 : null;
  const directory = (index: number) => {
    if (
      directories === null ||
      directories + index * 8 + 8 > optional + optionalSize
    )
      return null;
    return {
      rva: data.getUint32(directories + index * 8, true),
      size: data.getUint32(directories + index * 8 + 4, true),
    };
  };
  const toOffset = (rva: number) => {
    const owner = sections.find(
      (section) =>
        rva >= section.rva &&
        rva - section.rva < Math.max(section.virtualSize, section.size),
    );
    return owner === undefined ? null : owner.offset + (rva - owner.rva);
  };
  let imports: number | null = null;
  const importDirectory = directory(1);
  if (importDirectory !== null) {
    imports = 0;
    const start =
      importDirectory.rva === 0 ? null : toOffset(importDirectory.rva);
    if (importDirectory.rva !== 0 && start === null)
      limitations.push("PE import directory RVA is not file-backed.");
    if (start !== null)
      for (
        let entry = start;
        entry + 20 <= bytes.length && imports < MAX_IMPORT_DESCRIPTORS;
        entry += 20
      ) {
        if (bytes.subarray(entry, entry + 20).every((byte) => byte === 0))
          break;
        imports++;
      }
  } else limitations.push("PE optional header has no import data directory.");
  const clr = directory(14);
  return {
    sections: sections.map(
      ({ rva: _rva, virtualSize: _size, ...section }) => section,
    ),
    coverage: "complete",
    limitations,
    peImportDescriptors: imports,
    peManaged: clr !== null && clr.rva !== 0 && clr.size !== 0,
  };
};

const parseMachoSegments = (bytes: Uint8Array): SectionParse => {
  const data = view(bytes);
  const magic = data.getUint32(0, false);
  const little = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const wide = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const header = wide ? 32 : 28;
  if (bytes.length < header)
    return {
      sections: [],
      coverage: "unparsed",
      limitations: ["Mach-O header is truncated."],
      peImportDescriptors: null,
      peManaged: false,
    };
  const commands = data.getUint32(16, little);
  const sections: RawSection[] = [];
  let cursor = header;
  for (let index = 0; index < Math.min(commands, MAX_SECTIONS); index++) {
    if (cursor + 8 > bytes.length) break;
    const command = data.getUint32(cursor, little);
    const size = data.getUint32(cursor + 4, little);
    if (size < 8 || cursor + size > bytes.length)
      return {
        sections: [],
        coverage: "unparsed",
        limitations: ["Mach-O load command extends past the file."],
        peImportDescriptors: null,
        peManaged: false,
      };
    if (command === 0x19 || command === 0x1) {
      const segment64 = command === 0x19;
      const offset = segment64
        ? Number(data.getBigUint64(cursor + 40, little))
        : data.getUint32(cursor + 32, little);
      const fileSize = segment64
        ? Number(data.getBigUint64(cursor + 48, little))
        : data.getUint32(cursor + 36, little);
      const initialProtection = data.getUint32(
        cursor + (segment64 ? 60 : 44),
        little,
      );
      if (fileSize > 0)
        sections.push({
          name: cString(bytes, cursor + 8, 16),
          offset,
          size: fileSize,
          executable: (initialProtection & 0x4) !== 0,
          writable: (initialProtection & 0x2) !== 0,
        });
    }
    cursor += size;
  }
  return {
    sections,
    coverage: "complete",
    limitations: [
      "Mach-O entries are segments; individual sections are not split out.",
    ],
    peImportDescriptors: null,
    peManaged: false,
  };
};

/** Read the file-backed section (or segment) table for supported formats. */
export const parseTriageSections = (
  bytes: Uint8Array,
  format: TriageFormat,
): SectionParse => {
  const notApplicable = (limitation?: string): SectionParse => ({
    sections: [],
    coverage: "not_applicable",
    limitations: limitation === undefined ? [] : [limitation],
    peImportDescriptors: null,
    peManaged: false,
  });
  if (format === "elf") return parseElfSections(bytes);
  if (format === "pe") return parsePeSections(bytes);
  if (format === "mach-o") return parseMachoSegments(bytes);
  if (format === "mach-o-universal")
    return notApplicable(
      "Universal Mach-O slices are not triaged individually; extract a slice to inspect its segments.",
    );
  return notApplicable();
};

/** Clamp a declared range to the file and measure its entropy. */
export const measureSections = (
  bytes: Uint8Array,
  parsed: SectionParse,
): { sections: TriageSection[]; limitations: string[] } => {
  const limitations: string[] = [];
  const sections = parsed.sections.map((section) => {
    const offset = Math.min(section.offset, bytes.length);
    const end = Math.min(section.offset + section.size, bytes.length);
    if (end - offset < section.size)
      limitations.push(
        `Section ${JSON.stringify(section.name)} declares ${section.size} bytes at offset ${section.offset}, but only ${end - offset} are in the file.`,
      );
    return {
      name: section.name,
      location: { offset, bytes: end - offset },
      entropy: shannonEntropy(bytes.subarray(offset, end)),
      executable: section.executable,
      writable: section.writable,
    };
  });
  return { sections, limitations };
};

const SECTION_FAMILIES: readonly (readonly [RegExp, string])[] = [
  [/^\.?UPX\d?$/i, "UPX"],
  [/^\.vmp\d$/i, "VMProtect"],
  [/^\.(?:themida|winlice)$/i, "Themida/WinLicense"],
  [/^\.(?:aspack|adata)$/i, "ASPack"],
  [/^\.?MPRESS\d$/i, "MPRESS"],
  [/^\.petite$/i, "Petite"],
  [/^\.nsp\d$/i, "NsPack"],
  [/^\.enigma\d$/i, "Enigma Protector"],
  [/^(?:pec\d|\.pec\d?)$/i, "PECompact"],
  [/^\.?MEW$/i, "MEW"],
  [/^\.(?:perplex|yP)$/i, "Yoda's Protector"],
  [/^\.?kkrunchy$/i, "kkrunchy"],
];

const SIGNATURES: readonly {
  readonly id: string;
  readonly family: string;
  readonly bytes: Buffer;
  readonly detail: string;
}[] = [
  {
    id: "upx-marker",
    family: "UPX",
    bytes: Buffer.from("UPX!", "latin1"),
    detail: "UPX packer header marker.",
  },
  {
    id: "go-buildinfo",
    family: "Go toolchain",
    bytes: Buffer.from("\xff Go buildinf:", "latin1"),
    detail:
      "Go build information header; use the Go tools for module and symbol recovery.",
  },
  {
    id: "pyinstaller-cookie",
    family: "PyInstaller",
    bytes: Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]),
    detail:
      "PyInstaller archive cookie; the payload is an embedded Python archive.",
  },
  {
    id: "confuserex-attribute",
    family: "ConfuserEx",
    bytes: Buffer.from("ConfusedByAttribute", "latin1"),
    detail: "ConfuserEx marker attribute in .NET metadata.",
  },
  {
    id: "nuitka-marker",
    family: "Nuitka",
    bytes: Buffer.from("NUITKA_ONEFILE_PARENT", "latin1"),
    detail: "Nuitka one-file bootstrap marker.",
  },
];

/** Observed byte markers and section names, plus clearly labelled heuristics. */
export const packerIndicators = (
  bytes: Uint8Array,
  format: TriageFormat,
  sections: readonly TriageSection[],
  parsed: SectionParse,
  wholeFileEntropy: number,
): PackerIndicator[] => {
  const indicators: PackerIndicator[] = [];
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (const signature of SIGNATURES) {
    const offset = buffer.indexOf(signature.bytes);
    if (offset >= 0)
      indicators.push({
        id: signature.id,
        kind: "signature",
        family: signature.family,
        detail: signature.detail,
        location: { offset, bytes: signature.bytes.length },
        confidence: "observed",
      });
  }
  for (const section of sections) {
    const family = SECTION_FAMILIES.find(([pattern]) =>
      pattern.test(section.name),
    )?.[1];
    if (family !== undefined)
      indicators.push({
        id: `section-name:${section.name}`,
        kind: "section-name",
        family,
        detail: `Section name ${JSON.stringify(section.name)} is characteristic of ${family}.`,
        location: section.location,
        confidence: "observed",
      });
  }
  if (sections.some((section) => section.name === ".gopclntab"))
    indicators.push({
      id: "go-pclntab-section",
      kind: "section-name",
      family: "Go toolchain",
      detail: "Go program-counter line table section.",
      location: sections.find((section) => section.name === ".gopclntab")!
        .location,
      confidence: "observed",
    });
  if (parsed.peManaged)
    indicators.push({
      id: "pe-clr-header",
      kind: "signature",
      family: ".NET (CLR)",
      detail:
        "PE carries a CLR runtime header; use the managed-code tools instead of a native disassembler.",
      location: null,
      confidence: "observed",
    });
  for (const section of sections) {
    if (
      section.executable === true &&
      section.entropy >= HIGH_ENTROPY_THRESHOLD
    )
      indicators.push({
        id: `high-entropy-executable:${section.name}`,
        kind: "heuristic",
        family: "packed or encrypted code",
        detail: `Executable section ${JSON.stringify(section.name)} has entropy ${section.entropy}, typical of compressed or encrypted bytes rather than machine code.`,
        location: section.location,
        confidence: "inferred",
      });
    if (section.executable === true && section.writable === true)
      indicators.push({
        id: `writable-executable:${section.name}`,
        kind: "heuristic",
        family: "self-modifying or unpacking stub",
        detail: `Section ${JSON.stringify(section.name)} is both writable and executable.`,
        location: section.location,
        confidence: "inferred",
      });
  }
  if (
    format === "pe" &&
    !parsed.peManaged &&
    parsed.peImportDescriptors !== null &&
    parsed.peImportDescriptors <= 2 &&
    sections.some((section) => section.entropy >= 7)
  )
    indicators.push({
      id: "sparse-imports-high-entropy",
      kind: "heuristic",
      family: "packed or encrypted code",
      detail: `PE imports from ${parsed.peImportDescriptors} DLL(s) and has a section with entropy of at least 7; packers usually resolve the real imports at runtime.`,
      location: null,
      confidence: "inferred",
    });
  if (
    sections.length === 0 &&
    bytes.length >= ENTROPY_WINDOW_BYTES &&
    wholeFileEntropy >= HIGH_ENTROPY_THRESHOLD
  )
    indicators.push({
      id: "high-entropy-file",
      kind: "heuristic",
      family: "compressed or encrypted data",
      detail: `Whole-file entropy is ${wholeFileEntropy}, typical of compressed or encrypted content.`,
      location: null,
      confidence: "inferred",
    });
  return indicators;
};
