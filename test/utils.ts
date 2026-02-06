import { describe, it, expect } from "vitest";
import { Convert } from "pvtsutils";
import { generateCertificateSerialNumber } from "../src/utils";

describe("generateCertificateSerialNumber", () => {

  it("should prepend 0x00 when MSB is set", () => {
    const input = "80010203";
    const serialNumber = generateCertificateSerialNumber(input);
    const hex = Convert.ToHex(serialNumber);
    expect(hex).toBe("0080010203");
  });

  it("should not prepend 0x00 when MSB is not set", () => {
    const input = "7f010203";
    const serialNumber = generateCertificateSerialNumber(input);
    const hex = Convert.ToHex(serialNumber);
    expect(hex).toBe("7f010203");
  });

  it("should remove leading zeros", () => {
    const input = "00010203";
    const serialNumber = generateCertificateSerialNumber(input);
    const hex = Convert.ToHex(serialNumber);
    expect(hex).toBe("010203");
  });

  it("should handle leading zeros followed by MSB set byte", () => {
    // 00 removed -> 80... -> MSB set -> prepend 00
    const input = "00800102";
    const serialNumber = generateCertificateSerialNumber(input);
    const hex = Convert.ToHex(serialNumber);
    expect(hex).toBe("00800102");
  });

  it("should generate random serial number if input is empty", () => {
      const serialNumber = generateCertificateSerialNumber(undefined);
      expect(serialNumber.byteLength).toBeGreaterThan(0);
  });

});
