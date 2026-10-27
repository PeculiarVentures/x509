import { describe, it, expect, beforeAll } from "vitest";
import * as x509 from "./index";
import { base64, toArrayBuffer } from "@peculiar/utils";

const crypto = x509.cryptoProvider.get();

describe("X509CrlGenerator", () => {
  let keys: CryptoKeyPair;
  const alg = {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  };

  beforeAll(async () => {
    keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  });

  // https://github.com/PeculiarVentures/x509/issues/122
  it("encodes CRL dates in whole seconds", async () => {
    const crl = await x509.X509CrlGenerator.create({
      issuer: "CN=Test CA",
      thisUpdate: new Date("2051-01-01T00:00:00.123Z"),
      nextUpdate: new Date("2052-01-01T00:00:00.5Z"),
      signingAlgorithm: alg,
      signingKey: keys.privateKey,
      entries: [{ serialNumber: "01", revocationDate: new Date("2051-02-01T00:00:00.999Z") }],
    });

    const der = new TextDecoder("latin1").decode(crl.rawData);
    expect(der.match(/\d{14}(?:\.\d+)?Z/g)).toEqual(["20510101000000Z", "20520101000000Z", "20510201000000Z"]);
  });

  describe("create", () => {
    it("should throw error on duplicate serial numbers", async () => {
      const serialNumber = "010203";

      await expect(
        x509.X509CrlGenerator.create({
          issuer: "CN=Test CA",
          thisUpdate: new Date(),
          signingAlgorithm: alg,
          signingKey: keys.privateKey,
          entries: [
            {
              serialNumber,
              revocationDate: new Date(),
            },
            {
              serialNumber,
              revocationDate: new Date(),
            },
          ],
        }),
      ).rejects.toThrow(`Certificate serial number ${serialNumber} already exists in tbsCertList`);
    });
  });
});

describe("crypto", () => {
  const crypto = x509.cryptoProvider.get();

  describe("X509 crl generator", () => {
    const pem =
      "MIICADCB6QIBATANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBDQRcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBEMCACAQ4XDTEwMDEwMTA4MzAwMFowDDAKBgNVHRUEAwoBATAgAgEPFw0xMDAxMDEwODMwMDFaMAwwCgYDVR0VBAMKAQGgLzAtMB8GA1UdIwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1rzrJMAoGA1UdFAQDAgEBMA0GCSqGSIb3DQEBCwUAA4IBAQA9vPMLiinD8G7FaoTsu8T2jUrTi1OLPHxKnrlBrAP/eHa+VQV1HJfY5Gjq1dpNgzZqDIgQM5QHPm0aSgMN7Ultx+XzbxRswLnwgQrZ7f76Tlky1I+jz7/p3AEynrNR72v64SZt46UhpSuWBHoF1uEVtgirTZNfOEaGUJTNOaTA5U55/iw9BKjHN0e/Vd7OGnrk5h6FsgWOiasGn6/tym9teDt/L2hlOdsZsvX1KPc0ExUHVjJIUBYTooqyy/CuTzFHla6RYVYvJuRF5qYCxa0GTZK3ImCtJ3XfsGdfLEJDZ7T17xBQHucMvIVLm6vY44WUy7PqQhZJskhJMEvj01ZE";

    it("generate ca and crl", async () => {
      const alg: EcdsaParams & EcKeyGenParams = {
        name: "ECDSA",
        hash: "SHA-256",
        namedCurve: "P-256",
      };
      const caKeys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
      expect(caKeys.publicKey).toBeTruthy();
      expect(caKeys.privateKey).toBeTruthy();
      const caCert = await x509.X509CertificateGenerator.create({
        serialNumber: "01",
        subject: "CN=Test CA",
        issuer: "CN=Test CA",
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2020/01/03"),
        signingAlgorithm: alg,
        publicKey: caKeys.publicKey,
        signingKey: caKeys.privateKey,
      });

      let ok = await caCert.verify({ date: new Date("2020/01/01 12:00") });
      expect(ok).toBe(true);

      const crlBase = new x509.X509Crl(toArrayBuffer(base64.decode(pem)));

      const crl = await x509.X509CrlGenerator.create({
        issuer: caCert.issuer,
        thisUpdate: new Date("2022/01/01"),
        nextUpdate: new Date("2022/12/12"),
        entries: [
          ...crlBase.entries,
          {
            serialNumber: "01",
            revocationDate: new Date("2022/01/01"),
            reason: x509.X509CrlReason.certificateHold,
            invalidity: new Date("2022/01/01"),
            issuer: "CN=Test, O=Дом",
          },
        ],
        signingAlgorithm: alg,
        signingKey: caKeys.privateKey,
      });

      ok = await crl.verify({ publicKey: await caCert.publicKey.export() });
      expect(ok).toBe(true);

      // console.log(crl.toString("text"));
    });
  });
});
