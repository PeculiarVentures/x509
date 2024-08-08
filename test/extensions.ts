import * as assert from "node:assert";
import { Crypto } from "@peculiar/webcrypto";
import { AuthorityInfoAccessExtension, AuthorityKeyIdentifierExtension, CRLDistributionPointsExtension, CertificateIdentifier } from "../src";
import { PublicKey } from "../src/public_key";


describe("Extensions", () => {
  describe("CRLDistributionPointsExtension", () => {
    context("create", () => {
      it("should create an instance from an array of URLs", () => {
        const urls = ["http://example.com"];
        const ext = new CRLDistributionPointsExtension(urls);
        assert.strictEqual(ext.toString("text"), [
          "CRL Distribution Points:",
          "  Distribution Point:",
          "    URL: http://example.com",
        ].join("\n"));
        assert.strictEqual(ext.toString("hex"), "30230603551d1f041c301a3018a016a0148612687474703a2f2f6578616d706c652e636f6d");
      });
    });
  });

  describe("AuthorityKeyIdentifierExtension", () => {
    let crypto: Crypto;
    let spki: BufferSource;

    before(async () => {
      crypto = new Crypto();
      const alg = { name: "ECDSA", namedCurve: "P-256" };
      const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
      spki = await crypto.subtle.exportKey("spki", keys.publicKey);
    });

    context("create", () => {
      it("should create an instance from a PublicKeyType", async () => {
        const publicKey = await PublicKey.create(spki);
        const ext = await AuthorityKeyIdentifierExtension.create(publicKey);
        assert(ext instanceof AuthorityKeyIdentifierExtension);
      });

      it("should create an instance from a CertificateIdentifier", async () => {
        const certId: CertificateIdentifier = {
          name: [],
          serialNumber: "1234567890abcdef"
        };
        const ext = await AuthorityKeyIdentifierExtension.create(certId);
        assert(ext instanceof AuthorityKeyIdentifierExtension);
        assert.deepStrictEqual(ext.certId, certId);
      });
    });
  });

  describe("AuthorityInfoAccessExtension", () => {
    const raw = Buffer.from("30818706082B06010505070101047B3079302406082B060105050730018618687474703A2F2F6F6373702E64696769636572742E636F6D305106082B060105050730028645687474703A2F2F636163657274732E64696769636572742E636F6D2F47656F5472757374476C6F62616C544C5352534134303936534841323536323032324341312E637274", "hex");
    it("should parse", () => {
      const ext = new AuthorityInfoAccessExtension(raw);
      assert.strictEqual(ext.toString("text"), [
        "Authority Info Access:",
        "  OCSP: http://ocsp.digicert.com",
        "  CA Issuers: http://cacerts.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA1.crt",
      ].join("\n"));
    });

    it("should create", () => {
      const ext = new AuthorityInfoAccessExtension({
        ocsp: ["http://ocsp.digicert.com"],
        caIssuers: ["http://cacerts.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA1.crt"],
      });
      assert.strictEqual(ext.toString("hex"), "30818706082b06010505070101047b3079302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d305106082b060105050730028645687474703a2f2f636163657274732e64696769636572742e636f6d2f47656f5472757374476c6f62616c544c5352534134303936534841323536323032324341312e637274");
    });

    it("should create with multiple values and check text", () => {
      const ext = new AuthorityInfoAccessExtension({
        ocsp: ["http://ocsp.digicert.com", "http://ocsp2.digicert.com"],
        caIssuers: [
          "http://cacerts.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA1.crt",
          "http://cacerts2.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA2.crt"
        ],
        caRepository: ["http://crls.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA1.crl"],
        timeStamping: ["http://tsa.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA1"],
      });
      assert.strictEqual(ext.toString("text"), [
        "Authority Info Access:",
        "  OCSP:",
        "    URL 1: http://ocsp.digicert.com",
        "    URL 2: http://ocsp2.digicert.com",
        "  CA Issuers:",
        "    URL 1: http://cacerts.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA1.crt",
        "    URL 2: http://cacerts2.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA2.crt",
        "  Time Stamping: http://tsa.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA1",
        "  CA Repository: http://crls.digicert.com/GeoTrustGlobalTLSRSA4096SHA2562022CA1.crl",
      ].join("\n"));
    });
  });
});