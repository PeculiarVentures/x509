import { describe, it, expect } from "vitest";
import * as x509 from "./index";

describe("crypto", () => {
  const crypto = x509.cryptoProvider.get();

  describe("Pkcs10CertificateRequestGenerator", () => {
    it("simple", async () => {
      const keys = await crypto.subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: "P-256",
        },
        false,
        ["sign", "verify"],
      );
      expect(keys.publicKey).toBeTruthy();
      expect(keys.privateKey).toBeTruthy();
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        keys,
        signingAlgorithm: {
          name: "ECDSA",
          hash: "SHA-256",
        },
      });

      expect(csr).toBeTruthy();
      expect(csr.subject).toBe("");
      expect(csr.attributes.length).toEqual(0);
      expect(csr.extensions.length).toEqual(0);
      expect(csr.signatureAlgorithm).toEqual({
        name: "ECDSA",
        hash: { name: "SHA-256" },
      });
      expect(csr.publicKey.algorithm).toEqual({
        name: "ECDSA",
        namedCurve: "P-256",
      });
    });

    it("with attributes and extensions", async () => {
      const keys = await crypto.subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: "P-384",
        },
        false,
        ["sign", "verify"],
      );
      expect(keys.publicKey).toBeTruthy();
      expect(keys.privateKey).toBeTruthy();
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: "CN=Test",
        keys,
        signingAlgorithm: {
          name: "ECDSA",
          hash: "SHA-384",
        },
        extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment)],
        attributes: [new x509.ChallengePasswordAttribute("password")],
      });

      expect(csr).toBeTruthy();
      expect(csr.subject).toBe("CN=Test");
      expect(csr.attributes.length).toEqual(2);
      expect(csr.extensions.length).toEqual(1);
      expect(csr.signatureAlgorithm).toEqual({
        name: "ECDSA",
        hash: { name: "SHA-384" },
      });
      expect(csr.publicKey.algorithm).toEqual({
        name: "ECDSA",
        namedCurve: "P-384",
      });
    });

    it("ECDSA K-256", async () => {
      const keys = await crypto.subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: "K-256",
        },
        false,
        ["sign", "verify"],
      );
      expect(keys.publicKey).toBeTruthy();
      expect(keys.privateKey).toBeTruthy();
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        keys,
        signingAlgorithm: {
          name: "ECDSA",
          hash: "SHA-256",
        },
      });

      expect(csr).toBeTruthy();
      expect(csr.subject).toBe("");
      expect(csr.attributes.length).toEqual(0);
      expect(csr.extensions.length).toEqual(0);
      expect(csr.signatureAlgorithm).toEqual({
        name: "ECDSA",
        hash: { name: "SHA-256" },
      });
      expect(csr.publicKey.algorithm).toEqual({
        name: "ECDSA",
        namedCurve: "K-256",
      });
    });
  });
});
