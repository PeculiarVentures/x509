import {
  describe, it, expect, beforeAll,
} from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import * as x509 from "../src";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

describe("X509Crl", () => {
  let keys: CryptoKeyPair;
  let crl: x509.X509Crl;
  const alg = {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  };
  const issuerName = "CN=Test CA, O=Test Org";
  const thisUpdate = new Date("2023-01-01T00:00:00Z");
  const nextUpdate = new Date("2023-01-08T00:00:00Z");
  const revokedSerial = "010203";
  const revocationDate = new Date("2023-01-02T00:00:00Z");

  beforeAll(async () => {
    keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

    crl = await x509.X509CrlGenerator.create({
      issuer: issuerName,
      thisUpdate,
      nextUpdate,
      signingAlgorithm: alg,
      signingKey: keys.privateKey,
      entries: [
        {
          serialNumber: revokedSerial,
          revocationDate,
          reason: x509.X509CrlReason.keyCompromise,
          invalidity: new Date("2023-01-01T12:00:00Z"),
        },
        {
          serialNumber: "040506", // Entry without optional fields
          revocationDate: new Date("2023-01-03T00:00:00Z"),
        },
      ],
      extensions: [
        new x509.BasicConstraintsExtension(true), // Just using some extension for testing
      ],
    });
  });

  it("should parse properties correctly", () => {
    expect(crl).toBeDefined();
    expect(crl.version).toBe(1); // v2
    expect(crl.issuer).toBe(issuerName);
    expect(crl.thisUpdate.getTime()).toBe(thisUpdate.getTime());
    expect(crl.nextUpdate?.getTime()).toBe(nextUpdate.getTime());
    expect(crl.signatureAlgorithm.name).toBe("ECDSA");
    expect(crl.signature).toBeDefined();
    expect(crl.tbs).toBeDefined();
  });

  it("should have correct entries", () => {
    expect(crl.entries.length).toBe(2);

    const entry1 = crl.entries[0];
    expect(entry1.serialNumber).toBe(revokedSerial);
    expect(entry1.revocationDate.getTime()).toBe(revocationDate.getTime());
    expect(entry1.reason).toBe(x509.X509CrlReason.keyCompromise);
    expect(entry1.invalidity?.getTime()).toBe(new Date("2023-01-01T12:00:00Z").getTime());

    const entry2 = crl.entries[1];
    expect(entry2.serialNumber).toBe("040506");
    expect(entry2.reason).toBeUndefined();
    expect(entry2.invalidity).toBeUndefined();
  });

  it("should handle extensions", () => {
    expect(crl.extensions.length).toBeGreaterThan(0);
    const ext = crl.getExtension<x509.BasicConstraintsExtension>("2.5.29.19");
    expect(ext).toBeDefined();
    // Use 'ca' not 'cA'
    expect(ext?.ca).toBe(true);

    const extByType = crl.getExtension(x509.BasicConstraintsExtension);
    expect(extByType).toBeDefined();
    expect(extByType?.ca).toBe(true);

    const exts = crl.getExtensions("2.5.29.19");
    expect(exts.length).toBe(1);

    const extsByType = crl.getExtensions(x509.BasicConstraintsExtension);
    expect(extsByType.length).toBe(1);
  });

  it("should verify signature with CryptoKey", async () => {
    const ok = await crl.verify({ publicKey: keys.publicKey });
    expect(ok).toBe(true);
  });

  it("should verify signature with PublicKey", async () => {
    const spki = await crypto.subtle.exportKey("spki", keys.publicKey);
    const publicKey = new x509.PublicKey(spki);
    const ok = await crl.verify({ publicKey });
    expect(ok).toBe(true);
  });

  it("should verify signature with X509Certificate", async () => {
    // Generate a self-signed cert with the same key
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      keys,
      name: issuerName,
      signingAlgorithm: alg,
      notBefore: thisUpdate,
      notAfter: nextUpdate,
    });

    const ok = await crl.verify({ publicKey: cert });
    expect(ok).toBe(true);
  });

  it("should fail verification with wrong key", async () => {
    const newKeys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    const ok = await crl.verify({ publicKey: newKeys.publicKey });
    expect(ok).toBe(false);
  });

  it("should find revoked certificate", () => {
    const entry = crl.findRevoked(revokedSerial);
    expect(entry).toBeDefined();
    expect(entry?.serialNumber).toBe(revokedSerial);

    const entryByCert = crl.findRevoked({ serialNumber: revokedSerial } as x509.X509Certificate);
    expect(entryByCert).toBeDefined();
    expect(entryByCert?.serialNumber).toBe(revokedSerial);

    const notFound = crl.findRevoked("000000");
    expect(notFound).toBeNull();
  });

  it("should get thumbprint", async () => {
    const thumbprint = await crl.getThumbprint();
    expect(thumbprint.byteLength).toBe(20); // SHA-1

    const thumbprint256 = await crl.getThumbprint("SHA-256");
    expect(thumbprint256.byteLength).toBe(32);
  });

  it("should construct from PEM", () => {
    const pem = crl.toString("pem");
    const crlFromPem = new x509.X509Crl(pem);
    expect(crlFromPem.issuer).toBe(crl.issuer);
  });

  it("should throw on creation with invalid args", () => {
      // Use an invalid string that looks somewhat like a string but isn't a valid format
      expect(() => new x509.X509Crl("invalid string")).toThrow();
  });

});

describe("X509CrlGenerator", () => {
  let keys: CryptoKeyPair;
  const alg = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  };

  beforeAll(async () => {
    keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  });

  it("should create CRL with RSA key", async () => {
    const crl = await x509.X509CrlGenerator.create({
      issuer: "CN=RSA CA",
      signingAlgorithm: alg,
      signingKey: keys.privateKey,
      entries: [
        {
          serialNumber: "1234",
          revocationDate: new Date(),
        }
      ]
    });

    expect(crl).toBeDefined();
    expect(crl.signatureAlgorithm.name).toBe("RSASSA-PKCS1-v1_5");
    const ok = await crl.verify({ publicKey: keys.publicKey });
    expect(ok).toBe(true);
  });

  it("should throw if duplicate entries", async () => {
    await expect(x509.X509CrlGenerator.create({
      issuer: "CN=Test",
      signingAlgorithm: alg,
      signingKey: keys.privateKey,
      entries: [
        { serialNumber: "01", revocationDate: new Date() },
        { serialNumber: "01", revocationDate: new Date() },
      ]
    })).rejects.toThrow("already exists");
  });

});