import { describe, it, expect, beforeAll } from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import { Convert, isEqual } from "pvtsutils";
import * as x509 from "../src";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

describe("OcspCertId", () => {
  const alg = {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  };
  let caCert: x509.X509Certificate;
  let userCert: x509.X509Certificate;
  let caKeys: CryptoKeyPair;

  beforeAll(async () => {
    caKeys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    caCert = await x509.X509CertificateGenerator.createSelfSigned({
      name: "CN=Test CA",
      keys: caKeys,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });
    const userKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    userCert = await x509.X509CertificateGenerator.create({
      subject: "CN=User",
      issuer: "CN=Test CA",
      publicKey: userKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });
  });

  it("computes SHA-1 CertID correctly", async () => {
    const certId = await x509.OcspCertId.create(caCert, userCert, "SHA-1", crypto);
    expect(certId.hashAlgorithm).toEqual({ name: "SHA-1" });
    expect(certId.issuerNameHash.byteLength).toBe(20);
    expect(certId.issuerKeyHash.byteLength).toBe(20);

    const issuerNameDer = caCert.subjectName.toArrayBuffer();
    const spki = AsnConvert.parse(caCert.publicKey.rawData, SubjectPublicKeyInfo);
    const expectedNameHash = await crypto.subtle.digest("SHA-1", issuerNameDer);
    const expectedKeyHash = await crypto.subtle.digest("SHA-1", spki.subjectPublicKey);
    expect(isEqual(certId.issuerNameHash, expectedNameHash)).toBe(true);
    expect(isEqual(certId.issuerKeyHash, expectedKeyHash)).toBe(true);
    expect(certId.serialNumber).toBe(userCert.serialNumber);
  });

  it("computes SHA-256 CertID correctly", async () => {
    const certId = await x509.OcspCertId.create(caCert, userCert, "SHA-256", crypto);
    expect(certId.hashAlgorithm).toEqual({ name: "SHA-256" });
    expect(certId.issuerNameHash.byteLength).toBe(32);
    expect(certId.issuerKeyHash.byteLength).toBe(32);

    const issuerNameDer = caCert.subjectName.toArrayBuffer();
    const spki = AsnConvert.parse(caCert.publicKey.rawData, SubjectPublicKeyInfo);
    const expectedNameHash = await crypto.subtle.digest("SHA-256", issuerNameDer);
    const expectedKeyHash = await crypto.subtle.digest("SHA-256", spki.subjectPublicKey);
    expect(isEqual(certId.issuerNameHash, expectedNameHash)).toBe(true);
    expect(isEqual(certId.issuerKeyHash, expectedKeyHash)).toBe(true);
  });

  it("supports SHA-384 and SHA-512", async () => {
    const certId384 = await x509.OcspCertId.create(caCert, userCert, "SHA-384", crypto);
    expect(certId384.issuerNameHash.byteLength).toBe(48);
    const certId512 = await x509.OcspCertId.create(caCert, userCert, "SHA-512", crypto);
    expect(certId512.issuerNameHash.byteLength).toBe(64);
  });

  it("equal compares CertIDs", async () => {
    const a = await x509.OcspCertId.create(caCert, userCert, "SHA-256", crypto);
    const b = await x509.OcspCertId.create(caCert, userCert, "SHA-256", crypto);
    expect(a.equal(b)).toBe(true);
    expect(b.equal(a)).toBe(true);

    const c = await x509.OcspCertId.create(caCert, userCert, "SHA-1", crypto);
    expect(a.equal(c)).toBe(false);
    expect(a.equal({} as unknown as x509.OcspCertId)).toBe(false);
  });
});

describe("OcspRequest", () => {
  const alg = {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  };
  let caCert: x509.X509Certificate;
  let userCert: x509.X509Certificate;
  let caKeys: CryptoKeyPair;

  beforeAll(async () => {
    caKeys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    caCert = await x509.X509CertificateGenerator.createSelfSigned({
      name: "CN=Test CA",
      keys: caKeys,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });
    const userKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    userCert = await x509.X509CertificateGenerator.create({
      subject: "CN=User",
      issuer: "CN=Test CA",
      publicKey: userKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });
  });

  it("creates request with default nonce", async () => {
    const req = await x509.OcspRequest.create({ issuer: caCert, certificates: [userCert] }, crypto);
    expect(req.requests.length).toBe(1);
    expect(req.nonce).toBeDefined();
    expect(req.nonce!.byteLength).toBe(16);
    expect(req.extensions.length).toBe(1);
    expect(req.extensions[0].type).toBe("1.3.6.1.5.5.7.48.1.2");
  });

  it("nonce round-trip", async () => {
    const req = await x509.OcspRequest.create({ issuer: caCert, certificates: [userCert] }, crypto);
    const parsed = new x509.OcspRequest(req.rawData);
    expect(parsed.requests.length).toBe(1);
    expect(parsed.requests[0].equal(req.requests[0])).toBe(true);
    expect(isEqual(parsed.nonce!, req.nonce!)).toBe(true);

    const nonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer;
    const req2 = await x509.OcspRequest.create(
      { issuer: caCert, certificates: [userCert], nonce },
      crypto,
    );
    expect(Convert.ToHex(req2.nonce!)).toBe(Convert.ToHex(nonce));
    const parsed2 = new x509.OcspRequest(req2.rawData);
    expect(Convert.ToHex(parsed2.nonce!)).toBe(Convert.ToHex(nonce));
  });

  it("creates request without nonce", async () => {
    const req = await x509.OcspRequest.create(
      { issuer: caCert, certificates: [userCert], nonce: false },
      crypto,
    );
    expect(req.nonce).toBeUndefined();
    expect(req.extensions.length).toBe(0);
    const parsed = new x509.OcspRequest(req.rawData);
    expect(parsed.nonce).toBeUndefined();
  });

  it("DER is stable", async () => {
    const req = await x509.OcspRequest.create(
      {
        issuer: caCert,
        certificates: [userCert],
        nonce: Convert.FromHex("0102030405060708090a0b0c0d0e0f10"),
      },
      crypto,
    );
    const der1 = req.rawData;
    const parsed = new x509.OcspRequest(der1);
    const der2 = parsed.rawData;
    expect(isEqual(der1, der2)).toBe(true);
  });

  it("uses PEM tags", async () => {
    const req = await x509.OcspRequest.create(
      { issuer: caCert, certificates: [userCert], nonce: false },
      crypto,
    );
    const pem = req.toString("pem");
    expect(pem).toContain("-----BEGIN OCSP REQUEST-----");
    expect(pem).toContain("-----END OCSP REQUEST-----");
    const parsed = new x509.OcspRequest(pem);
    expect(parsed.requests[0].equal(req.requests[0])).toBe(true);

    expect(x509.PemConverter.OcspRequestTag).toBe("OCSP REQUEST");
    expect(x509.PemConverter.OcspResponseTag).toBe("OCSP RESPONSE");
  });

  it("supports multiple certificates", async () => {
    const userKeys2 = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const userCert2 = await x509.X509CertificateGenerator.create({
      subject: "CN=User2",
      issuer: "CN=Test CA",
      publicKey: userKeys2.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });
    const req = await x509.OcspRequest.create(
      { issuer: caCert, certificates: [userCert, userCert2], nonce: false },
      crypto,
    );
    expect(req.requests.length).toBe(2);
  });
});
