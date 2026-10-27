import { describe, it, expect } from "vitest";
import { hex } from "@peculiar/utils";
import { assertSingleAsnElement, normalizeCertificateSerialNumber } from "./utils";

describe("normalizeCertificateSerialNumber", () => {
  // Same hex input handling as pvtsutils 1.x Convert.FromHex, which v2 used.
  it.each([
    ["01", "01"],
    ["1", "01"],
    ["abc", "0abc"],
    ["ABCD", "00abcd"],
    ["01 02\n03\t04\r05", "0102030405"],
    ["80", "0080"],
    ["000001", "01"],
    ["", "00"],
  ])("reads %j as %s", (input, expected) => {
    expect(hex.encode(normalizeCertificateSerialNumber(input))).toBe(expected);
  });

  it.each(["0x01", "01:02", "01-02", "zz"])("rejects %j", (input) => {
    expect(() => normalizeCertificateSerialNumber(input)).toThrow(TypeError);
  });
});

describe("assertSingleAsnElement", () => {
  it.each([
    ["short form length", "0403010203"],
    ["long form length", `048180${"00".repeat(128)}`],
    ["two length octets", `04820100${"00".repeat(256)}`],
    ["high tag number form", "9f8101020102"],
    ["indefinite length (not checked)", "308004010100000401aa"],
  ])("accepts %s", (_name, text) => {
    expect(() => assertSingleAsnElement(hex.decode(text))).not.toThrow();
  });

  it.each([
    ["a second element", "04030102030401aa"],
    ["one trailing byte", "040301020300"],
    ["long form length", `048180${"00".repeat(128)}00`],
    ["high tag number form", "9f810102010200"],
  ])("rejects trailing data after %s", (_name, text) => {
    expect(() => assertSingleAsnElement(hex.decode(text))).toThrow(/Unexpected data after the ASN\.1 structure: \d+ trailing bytes/);
  });
});
