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

  it("#74 - Intermittent ERR_OSSL_ASN1_ILLEGAL_PADDING error with serial numbers starting with 80", async () => {
    // https://github.com/PeculiarVentures/x509/issues/74

    const keys = await crypto.subtle.generateKey({
      name: "ECDSA",
      namedCurve: "P-256",
    }, true, ["sign", "verify"]);

    // Test problematic serial numbers from the issue
    const problematicSerialNumbers = [
      "80048117884272",
      "80284629184668",
      "80290967596123",
      "8070459553297620",
      "801234"
    ];

    for (const serialNumber of problematicSerialNumbers) {
      // This should not throw an error during certificate generation
      const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber,
        name: "CN=Test, O=Test Org",
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2020/01/02"),
        signingAlgorithm: {
          name: "ECDSA",
          hash: "SHA-256",
        },
        keys: keys
      }, crypto);

      // Verify the certificate was created and can be parsed
      assert.ok(cert, `Certificate should be created with serial number ${serialNumber}`);
      assert.strictEqual(cert.serialNumber, serialNumber, `Serial number should match ${serialNumber}`);

      // Verify certificate can be converted to PEM and back
      const pemString = cert.toString("pem");
      assert.ok(pemString.includes("BEGIN CERTIFICATE"), "Should generate valid PEM");

      // Verify certificate can be parsed back
      const parsedCert = new x509.X509Certificate(pemString);
      assert.strictEqual(parsedCert.serialNumber, serialNumber, `Parsed serial number should match ${serialNumber}`);
    }
  });
});