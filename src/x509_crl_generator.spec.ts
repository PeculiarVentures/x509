import { describe, it, expect, beforeAll } from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import * as x509 from "./index";
import { Convert } from "pvtsutils";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

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
  const crypto = new Crypto();
  x509.cryptoProvider.set(crypto);

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

      const crlBase = new x509.X509Crl(Convert.FromBase64(pem));

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
