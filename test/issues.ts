import { webcrypto } from "node:crypto";
import {
  describe, it, expect,
} from "vitest";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import * as x509 from "../src";

const crypto = webcrypto as globalThis.Crypto;

describe("issues", () => {
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

    const chain = new x509.X509ChainBuilder({ certificates: [rootCert, intermediateCert] });
    const items = await chain.build(leafCert, crypto);
    expect(items.length).toBe(3);
  });

  it("#95 - X509 Subject name parsing incorrect if attribute value is a single character", () => {
    // https://github.com/PeculiarVentures/x509/issues/95

    // Test case 1: CN=t,OU=x,O=y
    const name1 = new x509.Name("CN=t,OU=x,O=y");
    const json1 = name1.toJSON();

    // Test case 2: CN=t,OU=x,O=y,C=z
    const name2 = new x509.Name("CN=t,OU=x,O=y,C=z");
    const json2 = name2.toJSON();
    expect(json1.length).toBe(3);
    expect(json1[0]).toEqual({ CN: ["t"] });
    expect(json1[1]).toEqual({ OU: ["x"] });
    expect(json1[2]).toEqual({ O: ["y"] });

    expect(json2.length).toBe(4);
    expect(json2[0]).toEqual({ CN: ["t"] });
    expect(json2[1]).toEqual({ OU: ["x"] });
    expect(json2[2]).toEqual({ O: ["y"] });
    expect(json2[3]).toEqual({ C: ["z"] });
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
      "801234",
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
        keys: keys,
      }, crypto);

      // Verify the certificate was created and can be parsed
      expect(cert).toBeTruthy();
      expect(cert.serialNumber).toBe(serialNumber);

      // Verify certificate can be converted to PEM and back
      const pemString = cert.toString("pem");
      expect(pemString.includes("BEGIN CERTIFICATE")).toBe(true);

      // Verify certificate can be parsed back
      const parsedCert = new x509.X509Certificate(pemString);
      expect(parsedCert.serialNumber).toBe(serialNumber);
    }
  });

  it("#122 - GeneralizedTime must not include fractional seconds (RFC 5280 §4.1.2.5.2)", async () => {
    // https://github.com/PeculiarVentures/x509/issues/122
    // When notAfter is beyond 2049, the encoding uses GeneralizedTime.
    // RFC 5280 §4.1.2.5.2 states GeneralizedTime values MUST NOT include fractional seconds.
    // Input Dates with non-zero milliseconds must be silently truncated to whole seconds.
    const keys = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );

    // Deliberate ms=500 to expose the fractional-seconds bug
    const notBefore = new Date("2026-06-15T12:00:00.500Z");
    const notAfter = new Date("2070-01-01T00:00:00.500Z"); // year > 2049 → GeneralizedTime

    const cert = await x509.X509CertificateGenerator.createSelfSigned(
      {
        serialNumber: "01",
        name: "CN=Issue 122 Test",
        notBefore,
        notAfter,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        keys,
      },
      crypto,
    );

    // Scan raw DER for GeneralizedTime tag (0x18) and check for decimal point (fractional seconds)
    const buf = Buffer.from(cert.rawData);
    const fractionalGeneralizedTimes: string[] = [];
    for (let i = 0; i < buf.length - 2; i++) {
      if (buf[i] === 0x18) { // ASN.1 GeneralizedTime tag
        const len = buf[i + 1];
        const str = buf.slice(i + 2, i + 2 + len).toString("ascii");
        if (str.includes(".")) {
          fractionalGeneralizedTimes.push(str);
        }
      }
    }
    expect(
      fractionalGeneralizedTimes,
      `GeneralizedTime must not contain fractional seconds. Found: ${fractionalGeneralizedTimes}`,
    ).toHaveLength(0);

    // Also verify via decoded validity that ms were stripped
    const asnCert = AsnConvert.parse(cert.rawData, Certificate);
    const decodedNotAfter = asnCert.tbsCertificate.validity.notAfter.getTime();
    expect(decodedNotAfter.getMilliseconds(), "Decoded notAfter must have ms=0").toBe(0);

    // Input Date must not be mutated
    expect(notAfter.getMilliseconds(), "Caller's notAfter Date must not be mutated").toBe(500);
  });
});
