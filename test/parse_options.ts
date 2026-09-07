import { describe, it, expect, beforeAll } from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificationRequest } from "@peculiar/asn1-csr";
import { id_pkcs9_at_extensionRequest } from "@peculiar/asn1-pkcs9";
import * as asn1X509 from "@peculiar/asn1-x509";
import * as asn1js from "asn1js";
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

    // NOTE: these assemble the structures from ASN.1 rather than through the
    // generators, so they exercise the parsing classes on their own. What the
    // generators themselves do with the options is covered separately below.

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

  // Creating is not parsing untrusted input.
  //
  // Almost every class here keeps its value as DER and re-derives the ASN.1 view by
  // parsing it again, so building an object involves several serialize/parse round-trips
  // of bytes this library produced moments earlier from structures the caller already
  // holds. Creating and reading back one certificate costs ~13 parses, none of which
  // crosses a trust boundary. Applying the asn1js limits to those capped what a caller
  // was allowed to build at 10000 nodes -- roughly 2500 RDNs -- and reported it as
  // "Maximum ASN.1 node count exceeded", which reads like a security rejection but was
  // the library refusing to build the caller's own data.
  //
  // The rule is now: limits apply to DER the caller handed us, not to DER we produced.
  // These two blocks pin both halves of it. Every test in the first block threw before
  // the rule was applied.
  describe("creation is not limited", () => {
    const alg = { name: "ECDSA", hash: "SHA-256", namedCurve: "P-256" };
    // 3000 RDNs is 12001 ASN.1 nodes; the default ceiling is 10000
    const largeName: x509.JsonName = Array.from({ length: 3000 }, (_, i) => ({ CN: [`n${i}`] }));
    const policies = Array.from({ length: 6000 }, (_, i) => `1.2.3.4.${i}`);
    const notBefore = new Date("2023-01-01T00:00:00Z");
    const notAfter = new Date("2023-01-08T00:00:00Z");

    let keys: CryptoKeyPair;

    beforeAll(async () => {
      keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    });

    it("X509CertificateGenerator builds a subject and issuer past the default limit", async () => {
      const cert = await x509.X509CertificateGenerator.create({
        serialNumber: "01",
        subject: largeName,
        issuer: largeName,
        notBefore,
        notAfter,
        signingAlgorithm: alg,
        signingKey: keys.privateKey,
        publicKey: keys.publicKey,
      });

      expect(cert.subjectName.toJSON()).toHaveLength(largeName.length);
      expect(cert.issuerName.toJSON()).toHaveLength(largeName.length);
    });

    it("X509CertificateGenerator builds and reads back a large extension", async () => {
      const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: "CN=Test",
        notBefore,
        notAfter,
        signingAlgorithm: alg,
        keys,
        extensions: [new x509.CertificatePolicyExtension(policies)],
      });

      // reading it back is the other half: the lazy accessors re-parse too
      const ext = cert.getExtension(x509.CertificatePolicyExtension);
      expect(ext?.policies).toHaveLength(policies.length);
    });

    it("X509CrlGenerator builds an issuer past the default limit", async () => {
      const crl = await x509.X509CrlGenerator.create({
        issuer: largeName,
        thisUpdate: notBefore,
        nextUpdate: notAfter,
        signingAlgorithm: alg,
        signingKey: keys.privateKey,
        extensions: [new x509.CertificatePolicyExtension(policies)],
      });

      expect(crl.issuerName.toJSON()).toHaveLength(largeName.length);
      expect((crl.extensions[0] as x509.CertificatePolicyExtension).policies).toHaveLength(
        policies.length,
      );
    });

    it("Pkcs10CertificateRequestGenerator builds a subject past the default limit", async () => {
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: largeName,
        keys,
        signingAlgorithm: alg,
      });

      expect(csr.subjectName.toJSON()).toHaveLength(largeName.length);
    });

    it("GeneralName builds a dn past the default limit", () => {
      const dn = largeName.map((rdn) => `CN=${rdn.CN[0]}`).join(", ");

      expect(new x509.GeneralName("dn", dn).type).toBe("dn");
    });

    it("AuthorityKeyIdentifierExtension builds from a large GeneralNames", () => {
      const nameBer = asn1js.fromBER(new x509.Name(largeName).toArrayBuffer(), {
        maxNodes: 100000,
      }).result;
      const generalNamesRaw = new asn1js.Sequence({
        value: [
          new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 4 }, value: [nameBer] }),
        ],
      }).toBER();
      // the GeneralNames itself is parsed from DER, so it still takes options
      const names = new x509.GeneralNames(generalNamesRaw, { berOptions: { maxNodes: 100000 } });

      const ext = new x509.AuthorityKeyIdentifierExtension({ name: names, serialNumber: "010203" });
      expect(ext.certId?.serialNumber).toBe("010203");
    });

    // KNOWN UPSTREAM DEFECT, reachable through the ordinary CSR API and not fixable
    // here. `Attribute` values are `AsnPropTypes.Any`, and `AsnAnyConverter.toASN`
    // re-parses each value with `fromBER` and no options on the *serialize* path
    // (@peculiar/asn1-schema 2.9.4, converters.js). The PKCS#10 generator puts the
    // whole serialized `Extensions` blob into one such value, so building a CSR walks
    // straight through it.
    //
    // What is rejected is not genuinely oversized: the blob has ~7 real nodes. asn1js
    // speculatively parses the payload of a primitive OCTET STRING on the shared node
    // counter and swallows the error without restoring the count, so a large extension
    // burns the budget and the *next* extension trips the check. That makes the failure
    // depend on extension order -- see the `it.fails` case below -- and it is why
    // `ExtensionsAttribute([bigExt])` alone works while `[bigExt, otherExt]` does not.
    //
    // Certificates and CRLs are unaffected: their extensions are a typed SEQUENCE
    // rather than an ANY, so nothing re-parses them on the way out.
    it("ExtensionsAttribute builds and reads back its extensions", () => {
      const attr = new x509.ExtensionsAttribute([new x509.CertificatePolicyExtension(policies)]);

      expect(attr.items).toHaveLength(1);
      expect((attr.items[0] as x509.CertificatePolicyExtension).policies).toHaveLength(
        policies.length,
      );
      expect(attr.type).toBe(id_pkcs9_at_extensionRequest);
    });
  });

  // Documents the upstream defect described above, through the public API that
  // reaches it. The body asserts the behaviour we *want*; `it.fails` records that it
  // does not hold yet, so this turns into a failure the day asn1js stops poisoning its
  // node counter (or asn1-schema forwards options on serialize) and can then be
  // promoted to a normal test. asn1js 3.0.10 / @peculiar/asn1-schema 2.9.4 are the
  // latest published versions as of writing, so there is nothing to upgrade to.
  it.fails("CSR extensions should build regardless of their order", async () => {
    const alg = { name: "ECDSA", hash: "SHA-256", namedCurve: "P-256" };
    const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    const large = new x509.CertificatePolicyExtension(
      Array.from({ length: 6000 }, (_, i) => `1.2.3.4.${i}`),
    );
    const smaller = new x509.BasicConstraintsExtension(true, 2);

    // this order works today, because the limit error is raised inside the trailing
    // OCTET STRING and discarded
    await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=Test",
      keys,
      signingAlgorithm: alg,
      extensions: [smaller, large],
    });

    // the same extensions the other way round currently throw "node count exceeded"
    await x509.Pkcs10CertificateRequestGenerator.create({
      name: "CN=Test",
      keys,
      signingAlgorithm: alg,
      extensions: [large, smaller],
    });
  });

  describe("parsing is still limited", () => {
    const alg = { name: "ECDSA", hash: "SHA-256", namedCurve: "P-256" };
    const largeName: x509.JsonName = Array.from({ length: 3000 }, (_, i) => ({ CN: [`n${i}`] }));
    const options = { berOptions: { maxNodes: 100000 } };

    let keys: CryptoKeyPair;

    beforeAll(async () => {
      keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    });

    it("DER a generator produced still needs raised options to parse back", async () => {
      // The generator can build it; taking those same bytes back in through a parse
      // constructor is a different question, and there the defaults still apply.
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: largeName,
        keys,
        signingAlgorithm: alg,
      });

      expect(() => new x509.Pkcs10CertificateRequest(csr.rawData)).toThrow(/node count/i);

      const parsed = new x509.Pkcs10CertificateRequest(csr.rawData, options);
      expect(parsed.subjectName.toJSON()).toHaveLength(largeName.length);
    });

    it("a raw publicKey is bounded by the defaults, and PublicKey is the way round it", async () => {
      // A raw SPKI is the one piece of DER a generator parses that the caller did not
      // get from this library, so the asn1js defaults still apply to it. There is no
      // option on the generator to change that, and none is needed: a real
      // SubjectPublicKeyInfo is 7-16 nodes against a 10000 node default. A caller who
      // does need to move the limits parses it themselves and passes the result.
      //
      // The payload below is nested 99 deep in `AlgorithmIdentifier.parameters`, which
      // is an ANY and so is parsed for real. Depth is used rather than node count
      // because `AsnAnyConverter.toASN` re-parses that value with no options on the way
      // back out, so a node-heavy payload would break serialization instead. Nested 99
      // the parameters still parse standalone under the default limit of 100, but the
      // two extra levels of SPKI wrapping put them over it.
      let parameters: asn1js.AsnType = new asn1js.Null();
      for (let i = 0; i < 99; i++) {
        parameters = new asn1js.Sequence({ value: [parameters] });
      }
      const spki = new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [new asn1js.ObjectIdentifier({ value: "1.2.3.4" }), parameters],
          }),
          new asn1js.BitString({ valueHex: new Uint8Array(32).buffer }),
        ],
      }).toBER();

      const params = {
        serialNumber: "01",
        subject: "CN=Test",
        issuer: "CN=Test",
        signingAlgorithm: alg,
        signingKey: keys.privateKey,
      };

      await expect(
        x509.X509CertificateGenerator.create({ ...params, publicKey: spki }),
      ).rejects.toThrow(/depth/i);

      // the escape hatch: parse it explicitly, under limits the caller chooses, and
      // hand the generator something already validated
      const publicKey = new x509.PublicKey(spki, { berOptions: { maxDepth: 1000 } });
      const cert = await x509.X509CertificateGenerator.create({ ...params, publicKey });

      const asn = AsnConvert.parse(cert.rawData, asn1X509.Certificate, {
        berOptions: { maxDepth: 1000 },
      });
      expect(AsnConvert.serialize(asn.tbsCertificate.subjectPublicKeyInfo).byteLength).toBe(
        spki.byteLength,
      );
    });

    it("GeneralName honours the options", () => {
      const nameBer = asn1js.fromBER(new x509.Name(largeName).toArrayBuffer(), {
        maxNodes: 100000,
      }).result;
      const raw = new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 4 },
        value: [nameBer],
      }).toBER();

      expect(() => new x509.GeneralName(raw)).toThrow(/node count/i);
      expect(new x509.GeneralName(raw, options).type).toBe("dn");
    });

    it("GeneralNames honours the options", () => {
      const nameBer = asn1js.fromBER(new x509.Name(largeName).toArrayBuffer(), {
        maxNodes: 100000,
      }).result;
      const raw = new asn1js.Sequence({
        value: [
          new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 4 }, value: [nameBer] }),
        ],
      }).toBER();

      expect(() => new x509.GeneralNames(raw)).toThrow(/node count/i);

      const names = new x509.GeneralNames(raw, options);
      expect(names.items).toHaveLength(1);
      expect(names.items[0].type).toBe("dn");
    });
  });
});
