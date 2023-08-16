
import * as assert from "node:assert";
import "reflect-metadata";
import { container } from "tsyringe";
import { AlgorithmProvider, diAlgorithmProvider } from "../src";

context("AlgorithmProvider", () => {

  let algorithmProvider: AlgorithmProvider;
  before(() => {
    algorithmProvider = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    assert.ok(algorithmProvider);
  });

  context("toAsnAlgorithm", () => {
    it("should convert RSASSA-PKCS1-v1_5 with string hash to AlgorithmIdentifier", () => {
      const alg = algorithmProvider.toAsnAlgorithm({
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-1",
      } as Algorithm);
      assert.strictEqual(alg.algorithm, "1.2.840.113549.1.1.5");
      assert.strictEqual(alg.parameters, null);
    });

    it("should convert RSASSA-PKCS1-v1_5 with HashAlgorithm to AlgorithmIdentifier", () => {
      const alg = algorithmProvider.toAsnAlgorithm({
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-1" },
      } as Algorithm);
      assert.strictEqual(alg.algorithm, "1.2.840.113549.1.1.5");
      assert.strictEqual(alg.parameters, null);
    });

    it("should convert RSASSA-PKCS1-v1_5 without hash to AlgorithmIdentifier", () => {
      const alg = algorithmProvider.toAsnAlgorithm({
        name: "RSASSA-PKCS1-v1_5",
      } as Algorithm);
      assert.strictEqual(alg.algorithm, "1.2.840.113549.1.1.1");
      assert.strictEqual(alg.parameters, null);
    });

    it("should throw error if RSA algorithm has hash like Algorithm but with not string name", () => {
      assert.throws(() => {
        algorithmProvider.toAsnAlgorithm({
          name: "RSASSA-PKCS1-v1_5",
          hash: { name: 1 },
        } as Algorithm);
      }, /Cannot get hash algorithm name/);
    });

    it("should convert ECDSA with SHA-1 to AlgorithmIdentifier", () => {
      const alg = algorithmProvider.toAsnAlgorithm({
        name: "ECDSA",
        hash: "SHA-1",
      } as Algorithm);
      assert.strictEqual(alg.algorithm, "1.2.840.10045.4.1");
      assert.strictEqual(alg.parameters, undefined);
    });

    it("should throw error if hash algorithm is not supported", async () => {
      assert.throws(() => algorithmProvider.toAsnAlgorithm({
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-2",
      } as Algorithm), /Cannot convert WebCrypto algorithm to ASN.1 algorithm/);
    });
  });

});