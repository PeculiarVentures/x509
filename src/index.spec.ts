import { webcrypto } from "node:crypto";
import { describe, it, expect } from "vitest";
import * as x509 from "./index";

const crypto = webcrypto as globalThis.Crypto;

describe("issues", () => {
  it("#67", async () => {
    // https://github.com/PeculiarVentures/x509/issues/67
    const rootKeys = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"],
    );
    const rootCert = await x509.X509CertificateGenerator.createSelfSigned(
      {
        serialNumber: "01",
        name: "CN=Root",
        notBefore: new Date(),
        notAfter: new Date(),
        keys: rootKeys,
        signingAlgorithm: {
          name: "ECDSA",
          hash: "SHA-256",
        },
      },
      crypto,
    );

    const intermediateKeys = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-384",
      },
      true,
      ["sign", "verify"],
    );
    const intermediateCert = await x509.X509CertificateGenerator.create(
      {
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
      },
      crypto,
    );

    const leafKeys = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-384",
      },
      true,
      ["sign", "verify"],
    );
    const leafCert = await x509.X509CertificateGenerator.create(
      {
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
      },
      crypto,
    );

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

    const keys = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"],
    );

    // Test problematic serial numbers from the issue
    const problematicSerialNumbers = ["80048117884272", "80284629184668", "80290967596123", "8070459553297620", "801234"];

    for (const serialNumber of problematicSerialNumbers) {
      // This should not throw an error during certificate generation
      const cert = await x509.X509CertificateGenerator.createSelfSigned(
        {
          serialNumber,
          name: "CN=Test, O=Test Org",
          notBefore: new Date("2020/01/01"),
          notAfter: new Date("2020/01/02"),
          signingAlgorithm: {
            name: "ECDSA",
            hash: "SHA-256",
          },
          keys: keys,
        },
        crypto,
      );

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

  it("#129 - trailing data after the DER structure is rejected", async () => {
    // https://github.com/PeculiarVentures/x509/issues/129
    const alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
    const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
    const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=Test", keys, signingAlgorithm: alg }, crypto);
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: "CN=Test", keys, signingAlgorithm: alg }, crypto);
    const crl = await x509.X509CrlGenerator.create({ issuer: "CN=Test", thisUpdate: new Date(), signingAlgorithm: alg, signingKey: keys.privateKey }, crypto);
    const pkcs7 = new x509.X509Certificates([cert]).export("raw");
    const append = (raw: ArrayBuffer, ...extra: number[]) => new Uint8Array([...new Uint8Array(raw), ...extra]);
    const error = /Unexpected data after the ASN\.1 structure/;

    // A second ASN.1 object (OCTET STRING aa), as in the issue, and a single trailing byte
    expect(() => new x509.X509Certificate(append(cert.rawData, 0x04, 0x01, 0xaa))).toThrow(error);
    expect(() => new x509.X509Certificate(append(cert.rawData, 0x00))).toThrow(error);
    expect(() => new x509.X509Certificate(x509.PemConverter.encode(append(cert.rawData, 0x00), "CERTIFICATE"))).toThrow(error);
    expect(() => new x509.Pkcs10CertificateRequest(append(csr.rawData, 0x00))).toThrow(error);
    expect(() => new x509.X509Crl(append(crl.rawData, 0x00))).toThrow(error);
    expect(() => new x509.PublicKey(append(cert.publicKey.rawData, 0x00))).toThrow(error);
    expect(() => new x509.Extension(append(new x509.BasicConstraintsExtension(true).rawData, 0x00))).toThrow(error);
    expect(() => new x509.X509Certificates(append(pkcs7, 0x00))).toThrow(error);

    // The exact encodings still parse, and rawData is the structure itself
    expect(new x509.X509Certificate(cert.rawData).rawData.byteLength).toBe(cert.rawData.byteLength);
    expect(new x509.X509Certificates(pkcs7)).toHaveLength(1);
  });
});

describe("crypto", () => {
  describe("issues", () => {
    it("#5 verification failing for x509 certificate with ECDSA", async () => {
      const ca = new x509.X509Certificate(
        "MIICVzCCAf2gAwIBAgIUH5dl9HNmcklznEOCTZxFIN65ugYwCgYIKoZIzj0EAwIwdTELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRAwDgYDVQQHEwdSYWxlaWdoMQ0wCwYDVQQKEwRFREpYMRUwEwYDVQQLEwxFREpYIFJvb3QgQ0ExFTATBgNVBAMTDEVESlggUm9vdCBDQTAeFw0yMTAxMDcwNzE2MDBaFw0yNDAxMDcwNzE2MDBaMH0xCzAJBgNVBAYTAlVTMRcwFQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEQMA4GA1UEBxMHUmFsZWlnaDENMAsGA1UEChMERURKWDEVMBMGA1UECxMMRURKWCBSb290IENBMR0wGwYDVQQDExRFREpYIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCDz/PG5Nw0Q45Vafk3p3RABsaiGgv5FPFEl+jfVVxw6o084dU+GibHJqL9JOk9t7zaXdc04oQSy0dkviV40HQGjYzBhMA4GA1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSQcYOQauj7nFQP4ZWKp59JtGVZajAfBgNVHSMEGDAWgBQU/uYHGGZLCS8dm9tCcaSBodnGnTAKBggqhkjOPQQDAgNIADBFAiEAgiDUpS14LEn9p/2u93L8+PsfvUHVD2WItO6cPfTT01cCIDr/RT6K5CmGnGgmFRrn/hZyGe3CvpzKfZqMX63UeoQQ",
      );
      const leaf = new x509.X509Certificate(
        "MIICgzCCAimgAwIBAgIUU3QVClDwfllZDosbQuijZEqeqN0wCgYIKoZIzj0EAwIwfTELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRAwDgYDVQQHEwdSYWxlaWdoMQ0wCwYDVQQKEwRFREpYMRUwEwYDVQQLEwxFREpYIFJvb3QgQ0ExHTAbBgNVBAMTFEVESlggSW50ZXJtZWRpYXRlIENBMB4XDTIxMDEwNzA3MTYwMFoXDTIyMDEwNzA3MTYwMFowaTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk5DMRAwDgYDVQQHEwdSZWxlaWdoMQ0wCwYDVQQKEwRFREpYMRQwEgYDVQQLEwtFbmdpbmVlcmluZzEWMBQGA1UEAxMNYXBpLmVkangudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKZwl6VQ9VZHpelF+ZhBkKY3N7f7qXvvIwDBIDpV18+iYs1r01Qoo2TwJh3/j/n87sqtm4nfuOBvjL8M/RUdDRWjgZowgZcwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQjjloUw1goFcY26GEIxnJlckH+JTAfBgNVHSMEGDAWgBSQcYOQauj7nFQP4ZWKp59JtGVZajAYBgNVHREEETAPgg1hcGkuZWRqeC50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIFYIeb08ZaNS6iFPrOdhCAZW10XF4C2oT9GwOMJ8tKp8AiEA25uqFuewgI0SuLTWX6MGa1pd9z0p2Ks+8/+1pY9PUGc=",
      );
      const ok = await leaf.verify({
        signatureOnly: true,
        publicKey: ca,
      });
      expect(ok).toBe(true);
    });
  });
});
