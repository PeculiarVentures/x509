import * as assert from "node:assert";
import { webcrypto } from "node:crypto";
import * as x509 from "../src";

const crypto = webcrypto as globalThis.Crypto;

context("issues", () => {
  it("#67", async () => {
    // https://github.com/PeculiarVentures/x509/issues/67
    const rootKeys = await crypto.subtle.generateKey({
      name: "ECDSA",
      namedCurve: "P-256",
    }, true, ["sign", "verify"]);
    const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=Root",
      notBefore: new Date(),
      notAfter: new Date(),
      keys: rootKeys,
      signingAlgorithm: {
        name: "ECDSA",
        hash: "SHA-256",
      },
    }, crypto);

    const intermediateKeys = await crypto.subtle.generateKey({
      name: "ECDSA",
      namedCurve: "P-384",
    }, true, ["sign", "verify"]);
    const intermediateCert = await x509.X509CertificateGenerator.create({
      serialNumber: "02",
      subject: "CN=Intermediate",
      issuer: rootCert.subject,
      notBefore: new Date(),
      notAfter: new Date(),
      signingKey: rootKeys.privateKey,
      publicKey: intermediateKeys.publicKey,
      signingAlgorithm: {
        name: "ECDSA",
        hash: "SHA-256",
      },
    }, crypto);

    const leafKeys = await crypto.subtle.generateKey({
      name: "ECDSA",
      namedCurve: "P-384",
    }, true, ["sign", "verify"]);
    const leafCert = await x509.X509CertificateGenerator.create({
      serialNumber: "03",
      subject: "CN=Leaf",
      issuer: intermediateCert.subject,
      notBefore: new Date(),
      notAfter: new Date(),
      signingKey: intermediateKeys.privateKey,
      publicKey: leafKeys.publicKey,
      signingAlgorithm: {
        name: "ECDSA",
        hash: "SHA-256",
      },
    }, crypto);

    // console.log([
    //   rootCert.toString("pem"),
    //   intermediateCert.toString("pem"),
    //   leafCert.toString("pem"),
    // ].join("\n"));

    const chain = new x509.X509ChainBuilder({
      certificates: [rootCert, intermediateCert],
    });
    const items = await chain.build(leafCert, crypto);
    assert.strictEqual(items.length, 3);
  });
});