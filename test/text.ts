import * as assert from "assert";
import { Crypto } from "@peculiar/webcrypto";
import * as x509 from "../src";

const crypto = new Crypto();

context("text", () => {

  context("extensions", async () => {
    const keyRaw = Buffer.from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh2Mkxa-PIkhoE_fo2RdBs1X5L8i6xkTEVSgiuLJILJG617ZgGfnKV_eHhEBPcoMk5KlqlSp7tlFyjnjYbl2pog", "base64url");

    const tests: {
      name: string;
      factory: () => Promise<x509.Extension>;
      want: string;
    }[] = [
        {
          name: "AKI from public key",
          factory: async () => {
            const key = await crypto.subtle.importKey(
              "spki",
              keyRaw,
              { name: "ECDSA", namedCurve: "P-256" },
              true, ["verify"]);

            return x509.AuthorityKeyIdentifierExtension.create(key, false, crypto);
          },
          want: [
            "Authority Key Identifier:",
            "  b2 94 47 5d 79 b4 99 8b  d6 bb 4e 56 26 87 dd d7",
            "  f0 f3 e9 48",
          ].join("\n"),
        },
        {
          name: "AKI from certificate id",
          factory: async () => {
            return x509.AuthorityKeyIdentifierExtension.create({
              serialNumber: "0102030405",
              name: new x509.GeneralNames([
                { type: "dns", value: "some.com" },
              ]),
            }, false, crypto);
          },
          want: [
            "Authority Key Identifier:",
            "  Authority Issuer:",
            "    DNS: some.com",
            "  Authority Serial Number: ",
            "    01 02 03 04 05",
          ].join("\n"),
        },
        {
          name: "Basic Constraints for Leaf",
          factory: async () => {
            return new x509.BasicConstraintsExtension(false, undefined, true);
          },
          want: [
            "Basic Constraints: critical",
          ].join("\n"),
        },
        {
          name: "Basic Constraints for CA",
          factory: async () => {
            return new x509.BasicConstraintsExtension(true, 0, true);
          },
          want: [
            "Basic Constraints: critical",
            "  CA: true",
            "  Path Length: 0"
          ].join("\n"),
        },
        {
          name: "Certificate Policies",
          factory: async () => {
            return new x509.CertificatePolicyExtension([
              "1.2.3.4.5",
              "1.2.3.4.5.6",
            ], false);
          },
          want: [
            "Certificate Policies:",
            "  Policy: 1.2.3.4.5",
            "  Policy: 1.2.3.4.5.6",
          ].join("\n"),
        },
        {
          name: "Extended Key Usages",
          factory: async () => {
            return new x509.ExtendedKeyUsageExtension([
              x509.ExtendedKeyUsage.serverAuth,
              x509.ExtendedKeyUsage.clientAuth,
            ]);
          },
          want: [
            "Extended Key Usages:",
            "  TLS WWW server authentication, TLS WWW client authentication",
          ].join("\n"),
        },
        {
          name: "Key Usages",
          factory: async () => {
            return new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true);
          },
          want: [
            "Key Usages: critical",
            "  crlSign, keyCertSign",
          ].join("\n"),
        },
        {
          name: "Subject Alternative Name",
          factory: async () => {
            return new x509.SubjectAlternativeNameExtension([
              { type: "dns", value: "some.com" },
            ]);
          },
          want: [
            "Subject Alternative Name:",
            "  DNS: some.com",
          ].join("\n"),
        },
        {
          name: "Subject Key Identifier",
          factory: async () => {
            const key = await crypto.subtle.importKey(
              "spki",
              keyRaw,
              { name: "ECDSA", namedCurve: "P-256" },
              true, ["verify"]);

            return await x509.SubjectKeyIdentifierExtension.create(key, false, crypto);
          },
          want: [
            "Subject Key Identifier:",
            "  b2 94 47 5d 79 b4 99 8b  d6 bb 4e 56 26 87 dd d7",
            "  f0 f3 e9 48",
          ].join("\n"),
        },
        {
          name: "Unknown Extension",
          factory: async () => {
            return new x509.Extension("1.2.3.4.5", false, new Uint8Array([2, 3, 1, 0, 1]));
          },
          want: [
            "1.2.3.4.5:",
            "  02 03 01 00 01",
          ].join("\n"),
        },
      ];
    for (const t of tests) {
      it(t.name, async () => {
        const ext = await t.factory();
        const text = ext.toString("text");
        assert.strictEqual(text, t.want);
      });
    }

  });

  context("TextConverter", () => {

    context("serialize", () => {
      const tests: {
        name: string;
        args: x509.TextObject;
        want: string;
      }[] = [
          {
            name: "Number",
            args: new x509.TextObject("Test", { "Number": 2 }),
            want: [
              "Test:",
              "  Number: 2",
            ].join("\n"),
          },
          {
            name: "String",
            args: new x509.TextObject("Test", { "String": "text" }),
            want: [
              "Test:",
              "  String: text",
            ].join("\n"),
          },
          {
            name: "Date",
            args: new x509.TextObject("Test", { "Date": new Date("2022-11-14T12:13:14.001Z") }),
            want: [
              "Test:",
              "  Date: Mon, 14 Nov 2022 12:13:14 GMT",
            ].join("\n"),
          },
          {
            name: "Buffer",
            args: new x509.TextObject("Test", {
              "Buffer": new Uint8Array([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                0, 1, 2, 3, 4, 5, 6, 7]),
            }),
            want: [
              "Test:",
              "  Buffer: ",
              "    00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f",
              "    00 01 02 03 04 05 06 07",
            ].join("\n"),
          },
          {
            name: "TextObject",
            args: new x509.TextObject("Test", { "Object": new x509.TextObject("Some", { "Version": 1 }) }),
            want: [
              "Test:",
              "  Object:",
              "    Version: 1",
            ].join("\n"),
          },
          {
            name: "TextObject[]",
            args: new x509.TextObject("Test", {
              "List": [
                new x509.TextObject("Some", { "Some": "Value" }),
                new x509.TextObject("Some", {}, "Default Value"),
              ],
            }),
            want: [
              "Test:",
              "  List:",
              "    Some: Value",
              "  List: Default Value",
            ].join("\n"),
          },
          {
            name: "empty key",
            args: new x509.TextObject("Test", { "": "Text" }),
            want: [
              "Test:",
              "  Text",
            ].join("\n"),
          },
        ];
      for (const t of tests) {
        it(t.name, () => {
          const text = x509.TextConverter.serialize(t.args);
          assert.strictEqual(text, t.want);
        });
      }

    });

  });

  context("pki objects", async () => {

    const tests: {
      name: string;
      factory: () => Promise<{
        toString(format?: string): string;
      }>;
      want: string;
    }[] = [
        {
          name: "Certificate",
          factory: async () => {
            return new x509.X509Certificate([
              "MIIBljCCATygAwIBAgIQAQIDBAUGBwgJCgsMDQ4PADAKBggqhkjOPQQDAjA2MRgw",
              "FgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0ExGjAYBgNVBAoTEVNvbWUgb3JnYW5pemF0",
              "aW9uMCQXDTIyMTEwOTEyMTMxNFoYEzIxMjIxMTA5MTIxMzE0LjAxNVowSjENMAsG",
              "A1UEAxMEVGVzdDEaMBgGA1UEChMRU29tZSBvcmdhbml6YXRpb24xHTAbBgkqhkiG",
              "9w0BCQEWDnNvbWVAZW1haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
              "nigiclJd1LARwEb8i4rQzWspjOqW8piqB4EtA6nhnWDDANhLm3AKOvQ2RAp/Cdg8",
              "tKBSSYxv6XE1Ge8NHsgA16MSMBAwDgYDVR0PAQH/BAQDAgbAMAoGCCqGSM49BAMC",
              "A0gAMEUCIGwtZZPzsy1FpzMgdB3LmzmHfagzq7qxoyQT4QY8j0ZzAiEA0S17Ns5D",
              "GfDTEuPiiVIRwQUrZnmFygb9WmedPK4ACx0=",
            ].join(""));
          },
          want: [
            "Certificate:",
            "  Data:",
            "    Version: v3 (2)",
            "    Serial Number: ",
            "      01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f 00",
            "    Signature Algorithm: ecdsaWithSHA256",
            "    Issuer: CN=Intermediate CA, O=Some organization",
            "    Validity:",
            "      Not Before: Wed, 09 Nov 2022 12:13:14 GMT",
            "      Not After: Mon, 09 Nov 2122 12:13:14 GMT",
            "    Subject: CN=Test, O=Some organization, E=some@email.com",
            "    Subject Public Key Info:",
            "      Algorithm: ecPublicKey",
            "        Named Curve: P-256",
            "      EC Point: ",
            "        04 9e 28 22 72 52 5d d4  b0 11 c0 46 fc 8b 8a d0",
            "        cd 6b 29 8c ea 96 f2 98  aa 07 81 2d 03 a9 e1 9d",
            "        60 c3 00 d8 4b 9b 70 0a  3a f4 36 44 0a 7f 09 d8",
            "        3c b4 a0 52 49 8c 6f e9  71 35 19 ef 0d 1e c8 00",
            "        d7",
            "    Extensions:",
            "      Key Usages: critical",
            "        digitalSignature, nonRepudiation",
            "  Signature:",
            "    Algorithm: ecdsaWithSHA256",
            "    30 45 02 20 6c 2d 65 93  f3 b3 2d 45 a7 33 20 74",
            "    1d cb 9b 39 87 7d a8 33  ab ba b1 a3 24 13 e1 06",
            "    3c 8f 46 73 02 21 00 d1  2d 7b 36 ce 43 19 f0 d3",
            "    12 e3 e2 89 52 11 c1 05  2b 66 79 85 ca 06 fd 5a",
            "    67 9d 3c ae 00 0b 1d",
          ].join("\n")
        },
        {
          name: "Certificates",
          factory: async () => {
            const cert = new x509.X509Certificate([
              "MIIBljCCATygAwIBAgIQAQIDBAUGBwgJCgsMDQ4PADAKBggqhkjOPQQDAjA2MRgw",
              "FgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0ExGjAYBgNVBAoTEVNvbWUgb3JnYW5pemF0",
              "aW9uMCQXDTIyMTEwOTEyMTMxNFoYEzIxMjIxMTA5MTIxMzE0LjAxNVowSjENMAsG",
              "A1UEAxMEVGVzdDEaMBgGA1UEChMRU29tZSBvcmdhbml6YXRpb24xHTAbBgkqhkiG",
              "9w0BCQEWDnNvbWVAZW1haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
              "nigiclJd1LARwEb8i4rQzWspjOqW8piqB4EtA6nhnWDDANhLm3AKOvQ2RAp/Cdg8",
              "tKBSSYxv6XE1Ge8NHsgA16MSMBAwDgYDVR0PAQH/BAQDAgbAMAoGCCqGSM49BAMC",
              "A0gAMEUCIGwtZZPzsy1FpzMgdB3LmzmHfagzq7qxoyQT4QY8j0ZzAiEA0S17Ns5D",
              "GfDTEuPiiVIRwQUrZnmFygb9WmedPK4ACx0=",
            ].join(""));

            return new x509.X509Certificates([cert, cert]);
          },
          want: [
            "X509Certificates:",
            "  Content Type: Signed Data",
            "  Content:",
            "    Version: v1 (1)",
            "    Certificates:",
            ...[0, 0].map(() => {
              return [
                "      Certificate:",
                "        Data:",
                "          Version: v3 (2)",
                "          Serial Number: ",
                "            01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f 00",
                "          Signature Algorithm: ecdsaWithSHA256",
                "          Issuer: CN=Intermediate CA, O=Some organization",
                "          Validity:",
                "            Not Before: Wed, 09 Nov 2022 12:13:14 GMT",
                "            Not After: Mon, 09 Nov 2122 12:13:14 GMT",
                "          Subject: CN=Test, O=Some organization, E=some@email.com",
                "          Subject Public Key Info:",
                "            Algorithm: ecPublicKey",
                "              Named Curve: P-256",
                "            EC Point: ",
                "              04 9e 28 22 72 52 5d d4  b0 11 c0 46 fc 8b 8a d0",
                "              cd 6b 29 8c ea 96 f2 98  aa 07 81 2d 03 a9 e1 9d",
                "              60 c3 00 d8 4b 9b 70 0a  3a f4 36 44 0a 7f 09 d8",
                "              3c b4 a0 52 49 8c 6f e9  71 35 19 ef 0d 1e c8 00",
                "              d7",
                "          Extensions:",
                "            Key Usages: critical",
                "              digitalSignature, nonRepudiation",
                "        Signature:",
                "          Algorithm: ecdsaWithSHA256",
                "          30 45 02 20 6c 2d 65 93  f3 b3 2d 45 a7 33 20 74",
                "          1d cb 9b 39 87 7d a8 33  ab ba b1 a3 24 13 e1 06",
                "          3c 8f 46 73 02 21 00 d1  2d 7b 36 ce 43 19 f0 d3",
                "          12 e3 e2 89 52 11 c1 05  2b 66 79 85 ca 06 fd 5a",
                "          67 9d 3c ae 00 0b 1d",
              ].join("\n");
            })
          ].join("\n")
        },
        {
          name: "PKCS#10 certificate request",
          factory: async () => new x509.Pkcs10CertificateRequest([
            "MIH/MIGnAgEAMA8xDTALBgNVBAMTBFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB",
            "BwNCAAR9n6IcxaoH5ftByzUxSVVC0OrIx4Ixc+dtopjY+z0/SVzepEEb3LGgHmWU",
            "4H/G2X1P/BMJzWKjrhl9D795pq7AoDYwFQYJKoZIhvcNAQkHMQgTBkFCQ0RFRjAd",
            "BgkqhkiG9w0BCQ4xEDAOMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDRwAwRAIg",
            "XMkMPhrRJT+tPPDMRwJLJqHslzscT8MHtvfa0Gg3q6kCIDu9ZvR8ad93PI5ZQZ2G",
            "7TxS/mRRYFgcgjC2lCFfkr8p",
          ].join("")),
          want: [
            "PKCS#10 Certificate Request:",
            "  Data:",
            "    Version: v1 (0)",
            "    Subject: CN=Test",
            "    Subject Public Key Info:",
            "      Algorithm: ecPublicKey",
            "        Named Curve: P-256",
            "      EC Point: ",
            "        04 7d 9f a2 1c c5 aa 07  e5 fb 41 cb 35 31 49 55",
            "        42 d0 ea c8 c7 82 31 73  e7 6d a2 98 d8 fb 3d 3f",
            "        49 5c de a4 41 1b dc b1  a0 1e 65 94 e0 7f c6 d9",
            "        7d 4f fc 13 09 cd 62 a3  ae 19 7d 0f bf 79 a6 ae",
            "        c0",
            "    Attributes:",
            "      Challenge Password: ABCDEF",
            "      Extensions:",
            "        Basic Constraints: critical",
            "  Signature:",
            "    Algorithm: ecdsaWithSHA256",
            "    30 44 02 20 5c c9 0c 3e  1a d1 25 3f ad 3c f0 cc",
            "    47 02 4b 26 a1 ec 97 3b  1c 4f c3 07 b6 f7 da d0",
            "    68 37 ab a9 02 20 3b bd  66 f4 7c 69 df 77 3c 8e",
            "    59 41 9d 86 ed 3c 52 fe  64 51 60 58 1c 82 30 b6",
            "    94 21 5f 92 bf 29",
          ].join("\n"),
        }
      ];
    for (const t of tests) {
      it(t.name, async () => {
        const obj = await t.factory();
        const text = obj.toString("text");
        assert.strictEqual(text, t.want);
      });
    }

  });

  context("attributes", async () => {
    const tests: {
      name: string;
      factory: () => Promise<x509.Attribute>;
      want: string;
    }[] = [
        {
          name: "Challenge Password",
          factory: async () => {
            return new x509.ChallengePasswordAttribute("ABCDEF");
          },
          want: [
            "Challenge Password: ABCDEF",
          ].join("\n"),
        },
        {
          name: "Extensions",
          factory: async () => {
            return new x509.ExtensionsAttribute([
              new x509.KeyUsagesExtension(x509.KeyUsageFlags.cRLSign, true),
            ]);
          },
          want: [
            "Extensions:",
            "  Key Usages: critical",
            "    crlSign",
          ].join("\n"),
        },
      ];
    for (const t of tests) {
      it(t.name, async () => {
        const ext = await t.factory();
        const text = ext.toString("text");
        assert.strictEqual(text, t.want);
      });
    }

  });

});
