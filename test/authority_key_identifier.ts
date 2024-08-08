import * as assert from "node:assert";
import { Crypto } from "@peculiar/webcrypto";
import { AuthorityKeyIdentifierExtension, CertificateIdentifier } from "../src";
import { PublicKey } from "../src/public_key";

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