import { deflateRawSync, deflateSync, gzipSync } from "node:zlib";
import { expect, it } from "vitest";

import {
  applyDecodeStep,
  convertNumber,
  DecodeStepFailure,
  detectMagic,
  previewText,
} from "./byteDecoding.js";
import type { DecodeStep } from "../../domain/native/byteDecoding.js";

const run = (bytes: Uint8Array, step: DecodeStep, maxBytes = 1 << 20) =>
  applyDecodeStep(bytes, step, maxBytes);
const text = (value: string) => Buffer.from(value, "latin1");

it("decodes standard, URL-safe and custom-alphabet base64", () => {
  expect(
    run(text("aGVsbG8gd29ybGQ="), { op: "base64_decode" }).toString(),
  ).toBe("hello world");
  expect(run(text("-_8"), { op: "base64_decode" })).toEqual(
    Buffer.from([0xfb, 0xff]),
  );
  const standard =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const custom = [...standard].reverse().join("");
  const encoded = [
    ...Buffer.from("secret config").toString("base64").replace(/=/g, ""),
  ]
    .map((char) => custom[standard.indexOf(char)])
    .join("");
  expect(
    run(text(encoded), { op: "base64_decode", alphabet: custom }).toString(),
  ).toBe("secret config");
  expect(() => run(text("not base64!"), { op: "base64_decode" })).toThrow(
    DecodeStepFailure,
  );
});

it("decodes RFC 4648 base32 and loose hex", () => {
  expect(
    run(text("MZXW6YTBOI======"), { op: "base32_decode" }).toString(),
  ).toBe("foobar");
  expect(run(text("0x41, 0x42 \\x43"), { op: "hex_decode" }).toString()).toBe(
    "ABC",
  );
  expect(() => run(text("abc"), { op: "hex_decode" })).toThrow(
    DecodeStepFailure,
  );
});

it("applies repeating XOR, byte arithmetic, NOT, bit rotation, reverse and slice", () => {
  expect(run(text("ABCD"), { op: "xor", key_hex: "0102" })).toEqual(
    Buffer.from([0x40, 0x40, 0x42, 0x46]),
  );
  expect(run(Buffer.from([0xff, 0x00]), { op: "add", value: 1 })).toEqual(
    Buffer.from([0x00, 0x01]),
  );
  expect(run(Buffer.from([0x00, 0x0f]), { op: "not" })).toEqual(
    Buffer.from([0xff, 0xf0]),
  );
  expect(
    run(Buffer.from([0x81]), { op: "rotate_bits", direction: "left", bits: 1 }),
  ).toEqual(Buffer.from([0x03]));
  expect(
    run(Buffer.from([0x03]), {
      op: "rotate_bits",
      direction: "right",
      bits: 1,
    }),
  ).toEqual(Buffer.from([0x81]));
  expect(run(text("abc"), { op: "reverse" }).toString()).toBe("cba");
  expect(
    run(text("abcdef"), { op: "slice", offset: 2, length: 3 }).toString(),
  ).toBe("cde");
  expect(() => run(text("abc"), { op: "slice", offset: 2, length: 5 })).toThrow(
    DecodeStepFailure,
  );
});

it("matches the classic RC4 test vector and supports keystream drop", () => {
  const cipher = run(text("Plaintext"), {
    op: "rc4",
    key_hex: Buffer.from("Key").toString("hex"),
    drop: 0,
  });
  expect(cipher.toString("hex")).toBe("bbf316e8d940af0ad3");
  const dropped = run(cipher, {
    op: "rc4",
    key_hex: Buffer.from("Key").toString("hex"),
    drop: 0,
  });
  expect(dropped.toString()).toBe("Plaintext");
  const withDrop = run(text("Plaintext"), {
    op: "rc4",
    key_hex: "4b6579",
    drop: 768,
  });
  expect(withDrop.equals(cipher)).toBe(false);
  expect(
    run(withDrop, { op: "rc4", key_hex: "4b6579", drop: 768 }).toString(),
  ).toBe("Plaintext");
});

it("decrypts the FIPS-197 AES-128 vector and reports a wrong key clearly", () => {
  const key = "000102030405060708090a0b0c0d0e0f";
  const plain = run(Buffer.from("69c4e0d86a7b0430d8cdb78070b4c55a", "hex"), {
    op: "aes_decrypt",
    mode: "ecb",
    key_hex: key,
    padding: "none",
  });
  expect(plain.toString("hex")).toBe("00112233445566778899aabbccddeeff");
  expect(() =>
    run(Buffer.alloc(16, 7), {
      op: "aes_decrypt",
      mode: "cbc",
      key_hex: key,
      iv_hex: key,
      padding: "pkcs7",
    }),
  ).toThrow(/key, IV, mode or padding/);
  expect(() =>
    run(Buffer.alloc(16), {
      op: "aes_decrypt",
      mode: "cbc",
      key_hex: key,
      padding: "pkcs7",
    }),
  ).toThrow(/16-byte iv_hex/);
});

it("inflates zlib, raw deflate and gzip within the output budget", () => {
  const payload = Buffer.from("x".repeat(5000));
  expect(run(deflateSync(payload), { op: "inflate", format: "zlib" })).toEqual(
    payload,
  );
  expect(
    run(deflateRawSync(payload), { op: "inflate", format: "raw" }),
  ).toEqual(payload);
  expect(run(gzipSync(payload), { op: "inflate", format: "gzip" })).toEqual(
    payload,
  );
  const bomb = deflateSync(Buffer.alloc(8 << 20));
  expect(() => run(bomb, { op: "inflate", format: "zlib" }, 1 << 20)).toThrow(
    /exceeds max_bytes/,
  );
});

it("names common magic numbers and renders printable previews", () => {
  expect(detectMagic(gzipSync(Buffer.from("a")))).toBe("gzip");
  expect(detectMagic(Buffer.from("MZ\x90\x00", "latin1"))).toBe("pe/dos-mz");
  expect(detectMagic(Buffer.from("%PDF-1.7"))).toBe("pdf");
  expect(detectMagic(Buffer.from("plain"))).toBeNull();
  expect(previewText(Buffer.from([0x41, 0x00, 0x42, 0xff]))).toBe("A.B.");
});

it("converts integers across bases, widths, byte orders and floats", () => {
  expect(convertNumber({ value: "0xdeadbeef" })).toMatchObject({
    width: 32,
    unsigned: "3735928559",
    signed: "-559038737",
    bytes_little_endian: "efbeadde",
    bytes_big_endian: "deadbeef",
  });
  expect(convertNumber({ value: "0x41424344" })).toMatchObject({
    ascii_big_endian: "ABCD",
    ascii_little_endian: "DCBA",
  });
  expect(convertNumber({ value: "-1" })).toMatchObject({
    width: 8,
    unsigned: "255",
    hex: "0xff",
  });
  expect(convertNumber({ value: "0x3f800000" }).float).toBe(1);
  expect(convertNumber({ value: "0x7fc00000" })).toMatchObject({
    float: null,
    float_note: "NaN",
  });
  expect(
    convertNumber({ bytes_hex: "efbeadde", byte_order: "little" }).hex,
  ).toBe("0xdeadbeef");
  expect(convertNumber({ value: "0o755", width: 16 }).unsigned).toBe("493");
  expect(convertNumber({ value: "0b1_0000_0000" }).width).toBe(16);
  expect(() => convertNumber({ value: "0x1ffffffffffffffff" })).toThrow(
    DecodeStepFailure,
  );
  expect(() => convertNumber({ value: "300", width: 8 })).toThrow(
    /fit in 8 bits/,
  );
});
