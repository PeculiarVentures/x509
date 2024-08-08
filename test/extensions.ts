import * as assert from "node:assert";
import { Crypto } from "@peculiar/webcrypto";
import { AuthorityKeyIdentifierExtension, CRLDistributionPointsExtension, CertificateIdentifier } from "../src";
import { PublicKey } from "../src/public_key";


describe("Extensions", () => {
  describe("CRLDistributionPointsExtension", () => {
    context("create", () => {
      it("should create an instance from an array of URLs", () => {
        const urls = ["http://example.com"];
        const ext = CRLDistributionPointsExtension.create(urls);
        assert.strictEqual(ext.toString("text"), [
          "CRL Distribution Points:",
          "  Distribution Point:",
          "    URL: http://example.com",
        ].join("\n"));
        assert.strictEqual(ext.toString("hex"), "30230603551d1f041c301a3018a016a0148612687474703a2f2f6578616d706c652e636f6d");
      });
    });
  });

  describe("AuthorityKeyIdentifierExtension", () => {
    let crypto: Crypto;
    let spki: BufferSource;

    before(async () => {
      crypto = new Crypto();
      const alg = { name: "ECDSA", namedCurve: "P-256" };
      const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
      spki = await crypto.subtle.exportKey("spki", keys.publicKey);
    });

    context("create", () => {
      it("should create an instance from a PublicKeyType", async () => {
        const publicKey = await PublicKey.create(spki);
        const ext = await AuthorityKeyIdentifierExtension.create(publicKey);
        assert(ext instanceof AuthorityKeyIdentifierExtension);
      });

      it("should create an instance from a CertificateIdentifier", async () => {
        const certId: CertificateIdentifier = {
          name: [],
          serialNumber: "1234567890abcdef"
        };
        const ext = await AuthorityKeyIdentifierExtension.create(certId);
        assert(ext instanceof AuthorityKeyIdentifierExtension);
        assert.deepStrictEqual(ext.certId, certId);
      });
    });
  });

});