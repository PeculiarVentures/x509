import { describe, it, expect, beforeAll } from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificationRequest } from "@peculiar/asn1-csr";
import { id_pkcs9_at_extensionRequest } from "@peculiar/asn1-pkcs9";
import * as asn1X509 from "@peculiar/asn1-x509";
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
  const csrBase64 =
    "MIICdDCCAVwCAQAwLzEtMA8GA1UEAxMIdGVzdE5hbWUwGgYJKoZIhvcNAQkBEw10ZXN0QG1haWwubm90MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArut7tLrb1BEHXImMTWipet+3/J2isn7mBv278oP7YyOkmX/Vzxvk9nvSc/B1wh6kSo6nfaxYacNNSP3r+WQYaTeLm5TsDbUfCJYtvvTuYH0GVTM8Qm7QhMZKnyUy/D60WNcRM4pnBDSEMpKppi7HhfL37DZpQnsQfr9r8LQPWZ9t/mf+FsSeWyQOQcz+ob6cODfNQIvbzpaXXdNpKIHLPW+/e4af5/WlZ9wL5Sy7kOf4X6nErdl74s1vSji9goANSQkd5TbswtFPRNybikrrisz0HtsIq2uTGDY6t3iOEHTe5qe/ux4anjbSqKVuIQEQWQOKb4h+mHTc+EC5yknihQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE7TU20ui1MLtxLM0UZMytYAjC7vtXxB5Vl6bzHUzZkVFW6oTeizqDxjeBtZ1SqErpgdyvzMvFSxF6f+679kl1/Zs2V0IPa4y58he3wTT/M1xCBN/bITY2cA4ETozbtK4cGoi6jY/0j8NcxTLfiBgwhE3ap+9GzLtWEhHWCXmpsohbvAktXSh1tLh4xmgoQoePEBSPbnaOmsonyzscKiBMASDvjrFdNbtD0uY2v/wYXwtRGvV/Q/O3lLWEosE4NdnZmgId4bm7ru48WucSnxuEJAkKUjDLrN0uqY/tKfX4Zy9w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U=";

  describe("X509Certificate", () => {
    it("parses with default limits", () => {
      const cert = new x509.X509Certificate(certPem);
      expect(cert.serialNumber).toBeTruthy();
    });

    it("throws when berOptions.maxDepth is too low", () => {
      expect(() => new x509.X509Certificate(certPem, { berOptions: { maxDepth: 1 } })).toThrow(
        /depth/i,
      );
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
      expect(() => new x509.PublicKey(spki, { berOptions: { maxDepth: 1 } })).toThrow(/depth/i);
    });
  });

  describe("Pkcs10CertificateRequest", () => {
    it("throws when berOptions.maxDepth is too low", () => {
      const raw = Convert.FromBase64(csrBase64);
      expect(() => new x509.Pkcs10CertificateRequest(raw, { berOptions: { maxDepth: 1 } })).toThrow(
        /depth/i,
      );
      // sanity: default parse works
      expect(new x509.Pkcs10CertificateRequest(raw).subject).toBeDefined();
    });
  });

  describe("X509Certificates (CMS)", () => {
    it("forwards berOptions through import()", () => {
      const cms = new x509.X509Certificates([new x509.X509Certificate(certPem)]).export("raw");
      expect(() => new x509.X509Certificates(cms, { berOptions: { maxDepth: 1 } })).toThrow(
        /depth/i,
      );
      // sanity: default import works
      expect(new x509.X509Certificates(cms).length).toBe(1);
    });

    it("keeps the collection and the options of the last successful import()", () => {
      const cms = new x509.X509Certificates([new x509.X509Certificate(certPem)]).export("raw");
      const certs = new x509.X509Certificates(cms);
      const asn = certs.toString("asn");

      expect(() => certs.import(cms, { berOptions: { maxDepth: 1 } })).toThrow(/depth/i);

      expect(certs).toHaveLength(1);
      expect(certs[0].serialNumber).toBe(new x509.X509Certificate(certPem).serialNumber);
      // the failed import must not have replaced the stored parse options
      expect(certs.toString("asn")).toBe(asn);
    });
  });

  describe("X509Crl", () => {
    let crlRaw: ArrayBuffer;

    beforeAll(async () => {
      const alg = {
        name: "ECDSA",
        hash: "SHA-256",
        namedCurve: "P-256",
      };
      const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
      const crl = await x509.X509CrlGenerator.create({
        issuer: "CN=Test CA",
        thisUpdate: new Date("2023-01-01T00:00:00Z"),
        nextUpdate: new Date("2023-01-08T00:00:00Z"),
        signingAlgorithm: alg,
        signingKey: keys.privateKey,
        entries: [
          {
            serialNumber: "010203",
            revocationDate: new Date("2023-01-02T00:00:00Z"),
          },
        ],
      });
      crlRaw = crl.rawData;
    });

    it("parses with default limits", () => {
      const crl = new x509.X509Crl(crlRaw);
      expect(crl.issuer).toBe("CN=Test CA");
    });

    it("throws when berOptions.maxDepth is too low", () => {
      expect(() => new x509.X509Crl(crlRaw, { berOptions: { maxDepth: 1 } })).toThrow(/depth/i);
    });

    it("a tight-but-sufficient maxDepth still allows inspection (re-parse reuses options)", () => {
      const crl = new x509.X509Crl(crlRaw, { berOptions: { maxDepth: 100 } });
      expect(typeof crl.toString("asn")).toBe("string");
      expect(typeof crl.toString("text")).toBe("string");
    });
  });

  // Extension and attribute values are parsed lazily, long after the top level
  // structure. Those parsers must reuse the options the object was created
  // with, otherwise raising the limits for a large input only helps the outer
  // structure while the nested values still fail on the asn1js defaults.
  describe("nested values", () => {
    const alg = {
      name: "ECDSA",
      hash: "SHA-256",
      namedCurve: "P-256",
    };
    // A certificate policies value of ~12000 ASN.1 nodes, above the 10000 default
    const policies = Array.from({ length: 6000 }, (_, i) => `1.2.3.4.${i}`);
    const berOptions = { maxNodes: 100000 };
    const notBefore = new Date("2023-01-01T00:00:00Z");
    const notAfter = new Date("2023-01-08T00:00:00Z");

    let keys: CryptoKeyPair;
    let largeExtension: asn1X509.Extension;

    beforeAll(async () => {
      keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
      largeExtension = AsnConvert.parse(
        new x509.CertificatePolicyExtension(policies).rawData,
        asn1X509.Extension,
      );
    });

    // NOTE: the generators parse their own output with the default limits, so
    // the structures carrying the large value are assembled from ASN.1.

    it("reuses the options for certificate extension values", async () => {
      const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: "CN=Test",
        notBefore,
        notAfter,
        signingAlgorithm: alg,
        keys,
      });
      const asn = AsnConvert.parse(cert.rawData, asn1X509.Certificate);
      asn.tbsCertificate.extensions = new asn1X509.Extensions([largeExtension]);
      const raw = AsnConvert.serialize(asn);

      expect(() => new x509.X509Certificate(raw)).toThrow(/node count/i);

      const parsed = new x509.X509Certificate(raw, { berOptions });
      const ext = parsed.getExtension(x509.CertificatePolicyExtension);
      expect(ext?.policies).toHaveLength(policies.length);
    });

    it("reuses the options for CRL entry extension values", async () => {
      const crl = await x509.X509CrlGenerator.create({
        issuer: "CN=Test CA",
        thisUpdate: notBefore,
        nextUpdate: notAfter,
        signingAlgorithm: alg,
        signingKey: keys.privateKey,
        entries: [
          {
            serialNumber: "010203",
            revocationDate: notBefore,
          },
        ],
      });
      const asn = AsnConvert.parse(crl.rawData, asn1X509.CertificateList);
      asn.tbsCertList.revokedCertificates![0].crlEntryExtensions = [largeExtension];
      const raw = AsnConvert.serialize(asn);

      expect(() => new x509.X509Crl(raw)).toThrow(/node count/i);

      const parsed = new x509.X509Crl(raw, { berOptions });
      const fromEntries = parsed.entries[0].extensions[0] as x509.CertificatePolicyExtension;
      expect(fromEntries.policies).toHaveLength(policies.length);
      const fromFindRevoked = parsed.findRevoked("010203")!
        .extensions[0] as x509.CertificatePolicyExtension;
      expect(fromFindRevoked.policies).toHaveLength(policies.length);
    });

    it("reuses the options for CSR attribute values", async () => {
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: "CN=Test",
        keys,
        signingAlgorithm: alg,
      });
      const asn = AsnConvert.parse(csr.rawData, CertificationRequest);
      asn.certificationRequestInfo.attributes.push(
        new asn1X509.Attribute({
          type: id_pkcs9_at_extensionRequest,
          values: [AsnConvert.serialize(new asn1X509.Extensions([largeExtension]))],
        }),
      );
      const raw = AsnConvert.serialize(asn);

      expect(() => new x509.Pkcs10CertificateRequest(raw)).toThrow(/node count/i);

      const parsed = new x509.Pkcs10CertificateRequest(raw, { berOptions });
      const ext = parsed.getExtension(
        asn1X509.id_ce_certificatePolicies,
      ) as x509.CertificatePolicyExtension;
      expect(ext.policies).toHaveLength(policies.length);
    });
  });
});
