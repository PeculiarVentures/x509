import { describe, it, expect, beforeAll } from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier, SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import { container } from "tsyringe";
import * as x509 from "../src";
import { AlgorithmProvider, diAlgorithmProvider } from "../src/algorithm";
import { diAsnSignatureFormatter, IAsnSignatureFormatter } from "../src/asn_signature_formatter";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

describe("OcspResponse", () => {
  const alg = {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  };
  let caKeys: CryptoKeyPair;
  let caCert: x509.X509Certificate;
  let userCert: x509.X509Certificate;
  let certId: x509.OcspCertId;
  let req: x509.OcspRequest;
  const now = new Date();

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
    certId = await x509.OcspCertId.create(caCert, userCert, "SHA-256", crypto);
    req = await x509.OcspRequest.create({ issuer: caCert, certificates: [userCert] }, crypto);
  });

  async function createGoodResponse(nonce?: ArrayBuffer) {
    return x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        signingKey: caKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [{ certId, status: "good", thisUpdate: now }],
        responseExtensions: nonce ? [x509.setNonce(nonce)] : undefined,
      },
      crypto,
    );
  }

  it("verifies good status", async () => {
    const resp = await createGoodResponse(req.nonce);
    const results = await resp.verify({ issuer: caCert, request: req, date: now });
    expect(results.length).toBe(1);
    expect(results[0].status).toBe("good");
    expect(results[0].nonceMatched).toBe(true);
    expect(results[0].producedAt.getTime()).toBe(now.getTime());
    expect(resp.basic?.responderId.type).toBe("byName");
  });

  it("handles revoked status as data", async () => {
    const revocationTime = new Date("2023-01-02T00:00:00Z");
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        signingKey: caKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [
          {
            certId,
            status: "revoked",
            revocationTime,
            revocationReason: 1,
            thisUpdate: now,
          },
        ],
      },
      crypto,
    );
    const results = await resp.verify({ issuer: caCert, date: now });
    expect(results[0].status).toBe("revoked");
    expect(results[0].revocationTime?.getTime()).toBe(revocationTime.getTime());
    expect(results[0].revocationReason).toBe(1);
  });

  it("handles unknown status as data", async () => {
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        signingKey: caKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [{ certId, status: "unknown", thisUpdate: now }],
      },
      crypto,
    );
    const results = await resp.verify({ issuer: caCert, date: now });
    expect(results[0].status).toBe("unknown");
  });

  it("verifies delegated responder with EKU", async () => {
    const respKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const ski = await x509.SubjectKeyIdentifierExtension.create(respKeys.publicKey);
    const responder = await x509.X509CertificateGenerator.create({
      subject: "CN=Responder",
      issuer: "CN=Test CA",
      publicKey: respKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
      extensions: [new x509.ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.9"]), ski],
    });
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        responderCert: responder,
        signingKey: respKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [{ certId, status: "good", thisUpdate: now }],
      },
      crypto,
    );
    expect(resp.basic?.certs.length).toBe(1);
    const results = await resp.verify({ issuer: caCert, date: now });
    expect(results[0].status).toBe("good");
  });

  it("rejects delegated responder with wrong EKU", async () => {
    const respKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const responder = await x509.X509CertificateGenerator.create({
      subject: "CN=Responder",
      issuer: "CN=Test CA",
      publicKey: respKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
      extensions: [new x509.ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.1"])],
    });
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        responderCert: responder,
        signingKey: respKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [{ certId, status: "good", thisUpdate: now }],
      },
      crypto,
    );
    await expect(resp.verify({ issuer: caCert, date: now })).rejects.toMatchObject({
      name: "OcspVerifyError",
      code: "authorization",
    });
  });

  it("rejects unauthorized responder", async () => {
    const otherKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const otherCa = await x509.X509CertificateGenerator.createSelfSigned({
      name: "CN=Other CA",
      keys: otherKeys,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });
    const badKeys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const badResponder = await x509.X509CertificateGenerator.create({
      subject: "CN=Bad",
      issuer: "CN=Other CA",
      publicKey: badKeys.publicKey,
      signingKey: otherKeys.privateKey,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
      extensions: [new x509.ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.9"])],
    });
    void otherCa;
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        responderCert: badResponder,
        signingKey: badKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [{ certId, status: "good", thisUpdate: now }],
      },
      crypto,
    );
    await expect(resp.verify({ issuer: caCert, date: now })).rejects.toMatchObject({
      code: "authorization",
    });
  });

  it("rejects tampered signature", async () => {
    const resp = await createGoodResponse();
    const tampered = new Uint8Array(resp.rawData);
    tampered[tampered.length - 5] ^= 0xff;
    const parsed = new x509.OcspResponse(tampered.buffer);
    await expect(parsed.verify({ issuer: caCert, date: now })).rejects.toMatchObject({
      code: "signature",
    });
  });

  it("rejects CertID mismatch", async () => {
    const otherKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const otherCa = await x509.X509CertificateGenerator.createSelfSigned({
      name: "CN=Other CA",
      keys: otherKeys,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });
    const badId = await x509.OcspCertId.create(otherCa, userCert, "SHA-256", crypto);
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        signingKey: caKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [{ certId: badId, status: "good", thisUpdate: now }],
      },
      crypto,
    );
    await expect(resp.verify({ issuer: caCert, date: now })).rejects.toMatchObject({
      code: "certId",
    });
  });

  it("rejects request CertID mismatch", async () => {
    const otherKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const otherUser = await x509.X509CertificateGenerator.create({
      subject: "CN=Other",
      issuer: "CN=Test CA",
      publicKey: otherKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });
    const otherId = await x509.OcspCertId.create(caCert, otherUser, "SHA-256", crypto);
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        signingKey: caKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [{ certId: otherId, status: "good", thisUpdate: now }],
        responseExtensions: req.nonce ? [x509.setNonce(req.nonce)] : undefined,
      },
      crypto,
    );
    await expect(resp.verify({ issuer: caCert, request: req, date: now })).rejects.toMatchObject({
      code: "certId",
    });
  });

  it("rejects expired response", async () => {
    const past = new Date(Date.now() - 3600 * 1000);
    const produced = new Date(Date.now() - 7200 * 1000);
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        signingKey: caKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: produced,
        responses: [{ certId, status: "good", thisUpdate: produced, nextUpdate: past }],
      },
      crypto,
    );
    await expect(resp.verify({ issuer: caCert, date: new Date() })).rejects.toMatchObject({
      code: "freshness",
    });
  });

  it("rejects future thisUpdate", async () => {
    const future = new Date(Date.now() + 3600 * 1000);
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        signingKey: caKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: new Date(),
        responses: [{ certId, status: "good", thisUpdate: future }],
      },
      crypto,
    );
    await expect(resp.verify({ issuer: caCert, date: new Date() })).rejects.toMatchObject({
      code: "freshness",
    });
  });

  it("rejects nonce mismatch", async () => {
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        signingKey: caKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [{ certId, status: "good", thisUpdate: now }],
        responseExtensions: [x509.setNonce(new Uint8Array([9, 9, 9, 9]))],
      },
      crypto,
    );
    await expect(resp.verify({ issuer: caCert, request: req, date: now })).rejects.toMatchObject({
      code: "nonce",
    });
  });

  it("throws StatusError for non-successful", async () => {
    const resp = x509.BasicOcspResponseGenerator.createError(
      x509.OCSPResponseStatus.malformedRequest,
    );
    expect(resp.status).toBe(x509.OCSPResponseStatus.malformedRequest);
    await expect(resp.verify({ issuer: caCert })).rejects.toMatchObject({
      name: "OcspResponseStatusError",
      status: x509.OCSPResponseStatus.malformedRequest,
    });
  });

  it("supports PEM tags and getSingle", async () => {
    const resp = await createGoodResponse();
    const pem = resp.toString("pem");
    expect(pem).toContain("-----BEGIN OCSP RESPONSE-----");
    const parsed = new x509.OcspResponse(pem);
    expect(parsed.status).toBe(x509.OCSPResponseStatus.successful);
    const single = parsed.getSingle(certId);
    expect(single).not.toBeNull();
    expect(single?.status).toBe("good");

    const otherId = await x509.OcspCertId.create(caCert, userCert, "SHA-1", crypto);
    expect(parsed.getSingle(otherId)).toBeNull();
  });

  it("verifies direct byKey responder", async () => {
    const spki = AsnConvert.parse(caCert.publicKey.rawData, SubjectPublicKeyInfo);
    const ski = await crypto.subtle.digest("SHA-1", spki.subjectPublicKey);

    const asnResponderId = new x509.ResponderID({ byKey: new x509.KeyHash(ski) });
    expect(asnResponderId.byKey).toBeDefined();

    const asnCertId = AsnConvert.parse(certId.rawData, x509.CertID);
    const asnStatus = new x509.CertStatus({ good: null });
    const asnSingle = new x509.SingleResponse({
      certID: asnCertId,
      certStatus: asnStatus,
      thisUpdate: now,
    });
    const asnResponseData = new x509.ResponseData({
      version: x509.Version.v1,
      responderID: asnResponderId,
      producedAt: now,
      responses: [asnSingle],
    });
    const tbs = AsnConvert.serialize(asnResponseData);
    const signingAlgorithm = {
      ...alg,
      ...caKeys.privateKey.algorithm,
    } as Algorithm;
    const signature = await crypto.subtle.sign(signingAlgorithm, caKeys.privateKey, tbs);
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    const asnSigAlg = algProv.toAsnAlgorithm(signingAlgorithm);
    const formatters = container
      .resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter)
      .reverse();
    let asnSig: ArrayBuffer | null = null;
    for (const f of formatters) {
      asnSig = f.toAsnSignature(signingAlgorithm, signature);
      if (asnSig) {
        break;
      }
    }
    if (!asnSig) {
      throw new Error("Cannot convert signature");
    }
    const asnBasic = new x509.BasicOCSPResponse({
      tbsResponseData: asnResponseData,
      signatureAlgorithm: asnSigAlg,
      signature: asnSig,
    });
    void AlgorithmIdentifier;
    const asnResponse = new x509.OCSPResponse({
      responseStatus: x509.OCSPResponseStatus.successful,
      responseBytes: new x509.ResponseBytes({
        responseType: "1.3.6.1.5.5.7.48.1.1",
        response: new OctetString(AsnConvert.serialize(asnBasic)),
      }),
    });
    const resp = new x509.OcspResponse(asnResponse);
    expect(resp.basic?.responderId.type).toBe("byKey");
    const results = await resp.verify({ issuer: caCert, date: now });
    expect(results[0].status).toBe("good");
  });
});
