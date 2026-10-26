import { describe, it, expect } from "vitest";
import { hex } from "@peculiar/utils";
import { normalizeCertificateSerialNumber } from "./utils";

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
