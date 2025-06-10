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

  it("#95 - X509 Subject name parsing incorrect if attribute value is a single character", () => {
    // https://github.com/PeculiarVentures/x509/issues/95

    // Test case 1: CN=t,OU=x,O=y
    const name1 = new x509.Name("CN=t,OU=x,O=y");
    const json1 = name1.toJSON();

    // Test case 2: CN=t,OU=x,O=y,C=z
    const name2 = new x509.Name("CN=t,OU=x,O=y,C=z");
    const json2 = name2.toJSON();
    assert.strictEqual(json1.length, 3, "Should have 3 RDN components");
    assert.deepStrictEqual(json1[0], { CN: ["t"] }, "CN should be 't'");
    assert.deepStrictEqual(json1[1], { OU: ["x"] }, "OU should be 'x'");
    assert.deepStrictEqual(json1[2], { O: ["y"] }, "O should be 'y'");

    assert.strictEqual(json2.length, 4, "Should have 4 RDN components");
    assert.deepStrictEqual(json2[0], { CN: ["t"] }, "CN should be 't'");
    assert.deepStrictEqual(json2[1], { OU: ["x"] }, "OU should be 'x'");
    assert.deepStrictEqual(json2[2], { O: ["y"] }, "O should be 'y'");
    assert.deepStrictEqual(json2[3], { C: ["z"] }, "C should be 'z'");
  });
});