import { describe, it, expect, beforeAll } from "vitest";
import { Convert } from "pvtsutils";
import * as asn1Schema from "@peculiar/asn1-schema";
import * as asn1CMS from "@peculiar/asn1-cms";
import * as x509 from "./index";

describe("crypto", () => {
  const crypto = x509.cryptoProvider.get();

  describe("X509Certificates", () => {
    const certs: x509.X509Certificates = new x509.X509Certificates();

    beforeAll(async () => {
      const alg: EcKeyGenParams & EcdsaParams = {
        name: "ECDSA",
        namedCurve: "P-256",
        hash: "SHA-256",
      };
      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
      expect(keys.publicKey).toBeTruthy();
      expect(keys.privateKey).toBeTruthy();
      certs.push(
        await x509.X509CertificateGenerator.createSelfSigned({
          name: "CN=Test #1",
          notBefore: new Date("2020/01/01"),
          notAfter: new Date("2020/02/01"),
          keys,
          serialNumber: "01",
          signingAlgorithm: alg,
        }),
      );
      certs.push(
        await x509.X509CertificateGenerator.createSelfSigned({
          name: "CN=Test #2",
          notBefore: new Date("2020/01/01"),
          notAfter: new Date("2020/02/01"),
          keys,
          serialNumber: "02",
          signingAlgorithm: alg,
        }),
      );
    });

    describe("import/export", () => {
      it("raw", async () => {
        const raw = await certs.export("raw");
        expect(raw instanceof ArrayBuffer).toBe(true);

        // check CMS structure
        const contentInfo = asn1Schema.AsnConvert.parse(raw, asn1CMS.ContentInfo);
        expect(contentInfo.contentType).toBe(asn1CMS.id_signedData);
        const signedData = asn1Schema.AsnConvert.parse(contentInfo.content, asn1CMS.SignedData);
        expect(signedData.version).toBe(1);
        expect(signedData.encapContentInfo.eContentType).toBe(asn1CMS.id_data);
        expect(signedData.encapContentInfo.eContent).toBeTruthy();
        if (signedData.encapContentInfo.eContent) {
          expect(signedData.encapContentInfo.eContent.single).toBeTruthy();
        }
        expect(signedData.certificates).toBeTruthy();
        if (signedData.certificates) {
          expect(signedData.certificates.length).toBe(2);
        }

        const certs2 = new x509.X509Certificates(raw);

        expect(certs2.length).toBe(2);
        expect(certs2[0].subject).toBe("CN=Test #1");
        expect(certs2[1].subject).toBe("CN=Test #2");
      });
      it("hex", async () => {
        const hex = await certs.export("hex");
        expect(Convert.isHex(hex)).toBe(true);
        const certs2 = new x509.X509Certificates(hex);

        expect(certs2.length).toBe(2);
        expect(certs2[0].subject).toBe("CN=Test #1");
        expect(certs2[1].subject).toBe("CN=Test #2");
      });
      it("pem", async () => {
        const pem = await certs.export("pem");
        expect(x509.PemConverter.isPem(pem)).toBe(true);
        const certs2 = new x509.X509Certificates(pem);

        expect(certs2.length).toBe(2);
        expect(certs2[0].subject).toBe("CN=Test #1");
        expect(certs2[1].subject).toBe("CN=Test #2");
      });
      it("base64", async () => {
        const base64 = await certs.export("base64");
        expect(Convert.isBase64(base64)).toBe(true);
        const certs2 = new x509.X509Certificates(base64);

        expect(certs2.length).toBe(2);
        expect(certs2[0].subject).toBe("CN=Test #1");
        expect(certs2[1].subject).toBe("CN=Test #2");
      });
      it("base64url", async () => {
        const base64url = await certs.export("base64url");
        expect(Convert.isBase64Url(base64url)).toBe(true);
        const certs2 = new x509.X509Certificates(base64url);

        expect(certs2.length).toBe(2);
        expect(certs2[0].subject).toBe("CN=Test #1");
        expect(certs2[1].subject).toBe("CN=Test #2");
      });
    });
  });
});
