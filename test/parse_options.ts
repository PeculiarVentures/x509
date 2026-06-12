import {
  describe, it, expect, beforeAll,
} from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import { Convert } from "pvtsutils";
import * as x509 from "../src";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

// https://github.com/PeculiarVentures/asn1-schema/pull/135
// Exposes `asn1js.fromBER` resource limits (maxDepth/maxNodes/maxContentLength)
// through `ParseOptions` so callers can tune them for untrusted input.
describe("parse options (berOptions)", () => {
  const certPem = [
    "-----BEGIN CERTIFICATE-----",
    "MIIDQzCCAuugAwIBAgICARYwCQYHKoZIzj0EATCBjjELMAkGA1UEBhMCUlUxDzAN",
    "BgNVBAgTBlJ1c3NpYTEPMA0GA1UEBxMGTW9zY293MRcwFQYDVQQKEw5GU1VFIFNU",
    "QyBBdGxhczENMAsGA1UECxMEVVpJUzEUMBIGA1UEAxMLQ1NDQS1SdXNzaWExHzAd",
    "BgkqhkiG9w0BCQEWEGNhbWFpbEBzdGNuZXQucnUwHhcNMjIwMjI4MTA0MjQ2WhcN",
    "MzQwMjI1MTA0MjQ2WjCBgDELMAkGA1UEBhMCUlUxDzANBgNVBAcMBk1vc2NvdzES",
    "MBAGA1UECgwJU1RDLUF0bGFzMQ0wCwYDVQQLDARVWklTMRwwGgYDVQQDDBNEb2N1",
    "bWVudF9TaWduZXJfMy41MR8wHQYJKoZIhvcNAQkBFhBjYW1haWxAc3RjbmV0LnJ1",
    "MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA",
    "AAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA////",
    "///////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVBMSd",
    "NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5",
    "RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA",
    "//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABNC/fO9tdWswlybyrKN5DWjq",
    "RAU9SDs4v8QAnFHysSgJa/THOmGfV4Xc1IIlU0PPVaacEmqh2Uonpl6UEI4QRVaj",
    "UjBQMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUh6hBQVQwYivY2H4KMSWkeXBD",
    "XakwHwYDVR0jBBgwFoAUhQxT9xYOXe9kpWd898GEkgXSspwwCQYHKoZIzj0EAQNH",
    "ADBEAiBtcZkULayUOn20W/FDY/XSa6gW4RCLLkbPDge7QZ3+mQIgMUxl931Jf6QP",
    "O7f6y6mZ+dfR9n9rrjl57E2GC6Co3P8=",
    "-----END CERTIFICATE-----",
  ].join("\n");

  // A valid PKCS#10 CSR (from the existing crypto tests)
  const csrBase64 = "MIICdDCCAVwCAQAwLzEtMA8GA1UEAxMIdGVzdE5hbWUwGgYJKoZIhvcNAQkBEw10ZXN0QG1haWwubm90MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArut7tLrb1BEHXImMTWipet+3/J2isn7mBv278oP7YyOkmX/Vzxvk9nvSc/B1wh6kSo6nfaxYacNNSP3r+WQYaTeLm5TsDbUfCJYtvvTuYH0GVTM8Qm7QhMZKnyUy/D60WNcRM4pnBDSEMpKppi7HhfL37DZpQnsQfr9r8LQPWZ9t/mf+FsSeWyQOQcz+ob6cODfNQIvbzpaXXdNpKIHLPW+/e4af5/WlZ9wL5Sy7kOf4X6nErdl74s1vSji9goANSQkd5TbswtFPRNybikrrisz0HtsIq2uTGDY6t3iOEHTe5qe/ux4anjbSqKVuIQEQWQOKb4h+mHTc+EC5yknihQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE7TU20ui1MLtxLM0UZMytYAjC7vtXxB5Vl6bzHUzZkVFW6oTeizqDxjeBtZ1SqErpgdyvzMvFSxF6f+679kl1/Zs2V0IPa4y58he3wTT/M1xCBN/bITY2cA4ETozbtK4cGoi6jY/0j8NcxTLfiBgwhE3ap+9GzLtWEhHWCXmpsohbvAktXSh1tLh4xmgoQoePEBSPbnaOmsonyzscKiBMASDvjrFdNbtD0uY2v/wYXwtRGvV/Q/O3lLWEosE4NdnZmgId4bm7ru48WucSnxuEJAkKUjDLrN0uqY/tKfX4Zy9w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U=";

  describe("X509Certificate", () => {
    it("parses with default limits", () => {
      const cert = new x509.X509Certificate(certPem);
      expect(cert.serialNumber).toBeTruthy();
    });

    it("throws when berOptions.maxDepth is too low", () => {
      expect(() => new x509.X509Certificate(certPem, { berOptions: { maxDepth: 1 } }))
        .toThrow(/depth/i);
    });

    it("a tight-but-sufficient maxDepth still allows inspection (re-parse reuses options)", () => {
      // Build the cert with explicit limits, then exercise the lazy re-parse paths
      // (toString("asn") and toTextObject) which must reuse the stored options.
      const cert = new x509.X509Certificate(certPem, { berOptions: { maxDepth: 100 } });
      expect(typeof cert.toString("asn")).toBe("string");
      expect(typeof cert.toString("text")).toBe("string");
    });
  });

  describe("PublicKey", () => {
    it("throws when berOptions.maxDepth is too low", () => {
      const spki = new x509.X509Certificate(certPem).publicKey.rawData;
      expect(() => new x509.PublicKey(spki, { berOptions: { maxDepth: 1 } }))
        .toThrow(/depth/i);
    });
  });

  describe("Pkcs10CertificateRequest", () => {
    it("throws when berOptions.maxDepth is too low", () => {
      const raw = Convert.FromBase64(csrBase64);
      expect(() => new x509.Pkcs10CertificateRequest(raw, { berOptions: { maxDepth: 1 } }))
        .toThrow(/depth/i);
      // sanity: default parse works
      expect(new x509.Pkcs10CertificateRequest(raw).subject).toBeDefined();
    });
  });

  describe("X509Certificates (CMS)", () => {
    it("forwards berOptions through import()", () => {
      const cms = new x509.X509Certificates([new x509.X509Certificate(certPem)]).export("raw");
      expect(() => new x509.X509Certificates(cms, { berOptions: { maxDepth: 1 } }))
        .toThrow(/depth/i);
      // sanity: default import works
      expect(new x509.X509Certificates(cms).length).toBe(1);
    });
  });

  describe("X509Crl", () => {
    let crlRaw: ArrayBuffer;

    beforeAll(async () => {
      const alg = {
        name: "ECDSA", hash: "SHA-256", namedCurve: "P-256",
      };
      const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
      const crl = await x509.X509CrlGenerator.create({
        issuer: "CN=Test CA",
        thisUpdate: new Date("2023-01-01T00:00:00Z"),
        nextUpdate: new Date("2023-01-08T00:00:00Z"),
        signingAlgorithm: alg,
        signingKey: keys.privateKey,
        entries: [{
          serialNumber: "010203", revocationDate: new Date("2023-01-02T00:00:00Z"),
        }],
      });
      crlRaw = crl.rawData;
    });

    it("parses with default limits", () => {
      const crl = new x509.X509Crl(crlRaw);
      expect(crl.issuer).toBe("CN=Test CA");
    });

    it("throws when berOptions.maxDepth is too low", () => {
      expect(() => new x509.X509Crl(crlRaw, { berOptions: { maxDepth: 1 } }))
        .toThrow(/depth/i);
    });

    it("a tight-but-sufficient maxDepth still allows inspection (re-parse reuses options)", () => {
      const crl = new x509.X509Crl(crlRaw, { berOptions: { maxDepth: 100 } });
      expect(typeof crl.toString("asn")).toBe("string");
      expect(typeof crl.toString("text")).toBe("string");
    });
  });
});
