import {
  describe, it, expect, beforeAll,
} from "vitest";
import "reflect-metadata";
import { container } from "tsyringe";
import { AlgorithmProvider, diAlgorithmProvider } from "../src";

describe("AlgorithmProvider", () => {
  let algorithmProvider: AlgorithmProvider;
  beforeAll(() => {
    algorithmProvider = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    expect(algorithmProvider).toBeTruthy();
  });

  describe("toAsnAlgorithm", () => {
    it("should convert RSASSA-PKCS1-v1_5 with string hash to AlgorithmIdentifier", () => {
      const alg = algorithmProvider.toAsnAlgorithm({
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-1",
      } as Algorithm);
      expect(alg.algorithm).toBe("1.2.840.113549.1.1.5");
      expect(alg.parameters).toBe(null);
    });

    it("should convert RSASSA-PKCS1-v1_5 with HashAlgorithm to AlgorithmIdentifier", () => {
      const alg = algorithmProvider.toAsnAlgorithm({
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-1" },
      } as Algorithm);
      expect(alg.algorithm).toBe("1.2.840.113549.1.1.5");
      expect(alg.parameters).toBe(null);
    });

    it("should convert RSASSA-PKCS1-v1_5 without hash to AlgorithmIdentifier", () => {
      const alg = algorithmProvider.toAsnAlgorithm({ name: "RSASSA-PKCS1-v1_5" } as Algorithm);
      expect(alg.algorithm).toBe("1.2.840.113549.1.1.1");
      expect(alg.parameters).toBe(null);
    });

    it("should throw error if RSA algorithm has hash like Algorithm but with not string name", () => {
      expect(() => {
        algorithmProvider.toAsnAlgorithm({
          name: "RSASSA-PKCS1-v1_5",
          hash: { name: 1 },
        } as Algorithm);
      }).toThrow(/Cannot get hash algorithm name/);
    });

    it("should convert ECDSA with SHA-1 to AlgorithmIdentifier", () => {
      const alg = algorithmProvider.toAsnAlgorithm({
        name: "ECDSA",
        hash: "SHA-1",
      } as Algorithm);
      expect(alg.algorithm).toBe("1.2.840.10045.4.1");
      expect(alg.parameters).toBe(undefined);
    });

    it("should throw error if hash algorithm is not supported", async () => {
      expect(() => algorithmProvider.toAsnAlgorithm({
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-2",
      } as Algorithm)).toThrow(/Cannot convert WebCrypto algorithm to ASN.1 algorithm/);
    });
  });
});
