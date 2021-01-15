import * as assert from "assert";
import { Convert } from "pvtsutils";
import { Crypto } from "@peculiar/webcrypto";
import * as asn1X509 from "@peculiar/asn1-x509";
import * as x509 from "../src";

context("crypto", () => {

  const crypto = new Crypto();
  x509.cryptoProvider.set(crypto);

  context("Name", () => {

    function assertName(name: asn1X509.Name, text: string) {
      // serialize
      const value = new x509.Name(name).toString();
      assert.strictEqual(value, text);

      // parse
      const name2 = new x509.Name(text);
      assert.strictEqual(name2.toString(), text);
    }

    it("Simple list of RDNs (joined by comma)", () => {
      const name = new asn1X509.Name([
        new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1X509.AttributeValue({ printableString: "Common Name" }) })]),
        new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "2.5.4.6", value: new asn1X509.AttributeValue({ printableString: "RU" }) })])
      ]);

      assertName(name, "CN=Common Name, C=RU");
    });

    it("Simple list of DNs (joined by +)", () => {
      const name = new asn1X509.Name([
        new asn1X509.RelativeDistinguishedName([
          new asn1X509.AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1X509.AttributeValue({ printableString: "Common Name" }) }),
          new asn1X509.AttributeTypeAndValue({ type: "2.5.4.6", value: new asn1X509.AttributeValue({ printableString: "RU" }) })]),
      ]);

      assertName(name, "CN=Common Name+C=RU");
    });

    it("Hexadecimal representation", () => {
      const name = new asn1X509.Name([
        new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ anyValue: new Uint8Array([0x04, 0x02, 0x48, 0x69]).buffer }) })]),
      ]);

      assertName(name, "1.2.3.4.5=#04024869");
    });

    context("Escaped chars", () => {

      it("# character at the beginning", () => {
        const name = new asn1X509.Name([
          new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: "#tag" }) })]),
        ]);

        assertName(name, "1.2.3.4.5=\\#tag");
      });

      it("space character at the beginning", () => {
        const name = new asn1X509.Name([
          new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: " tag" }) })]),
        ]);

        assertName(name, "1.2.3.4.5=\\ tag");
      });

      it("space character at the end", () => {
        const name = new asn1X509.Name([
          new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: "tag " }) })]),
        ]);

        assertName(name, "1.2.3.4.5=tag\\ ");
      });

      it("special characters", () => {
        const name = new asn1X509.Name([
          new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: ",+\"\\<>;" }) })]),
        ]);

        assertName(name, "1.2.3.4.5=\\,\\+\\\"\\\\\\<\\>\\;");
      });

      it("unknown characters", () => {
        const name = new asn1X509.Name([
          new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: "Hello\nworld" }) })]),
        ]);

        assertName(name, "1.2.3.4.5=Hello\\0Aworld");
      });

      it("parse quoted value", () => {
        const text = "CN=\"here is a test message with \\\",\\\" character\"+CN=It includes \\< \\> \\+ escaped characters\\ ";
        const name = new x509.Name(text);
        assert.strictEqual(name.toString(), "CN=here is a test message with \\\"\\,\\\" character+CN=It includes \\< \\> \\+ escaped characters\\ ");
      });

    });

    it("json", () => {
      const text = "CN=name1, CN=name2+CN=name3+E=some@email.com, 1.2.3.4.5=#04020102+DC=some.com";
      const name = new x509.Name(text);

      const json: x509.JsonName = [
        { CN: ["name1"] },
        { CN: ["name2", "name3"], E: ["some@email.com"] },
        { "1.2.3.4.5": ["#04020102"], DC: ["some.com"] },
      ];
      assert.deepStrictEqual(name.toJSON(), json);

      const name2 = new x509.Name(json);
      assert.strictEqual(name2.toString(), text);

      assert.strictEqual(Convert.ToHex(name.toArrayBuffer()), "3071310e300c060355040313056e616d65313139300c060355040313056e616d6532300c060355040313056e616d6533301b06092a864886f70d010901160e736f6d6540656d61696c2e636f6d3124300a06042a030405040201023016060a0992268993f22c6401191608736f6d652e636f6d");
    });

    it("parse with odd , marks", () => {
      const text = "  ,  , ,  CN=Some Name, O=Peculiar Ventures\\, LLC, O=\"Peculiar Ventures, LLC\", CN=name2+O=Test+CN=name3+E=some@email.com, 1.2.3.4.5=#04020102+DC=some.com,, , ";
      const name = new x509.Name(text);

      assert.strictEqual(name.toString(), "CN=Some Name, O=Peculiar Ventures\\, LLC, O=Peculiar Ventures\\, LLC, CN=name2+O=Test+CN=name3+E=some@email.com, 1.2.3.4.5=#04020102+DC=some.com");
    });

    it("extra names", () => {
      const text = "Email=some@email.com, IP=192.168.0.1, GUID={8ee13e53-2c1c-42bb-8df7-39927c0bdbb6}";
      const name = new x509.Name(text, {
        "Email": "1.2.3.4.5.1",
        "IP": "1.2.3.4.5.2",
        "GUID": "1.2.3.4.5.3",
      });

      assert.strictEqual(Convert.ToHex(name.toArrayBuffer()), "30663119301706052a03040501130e736f6d6540656d61696c2e636f6d3116301406052a03040502130b3139322e3136382e302e313131302f06052a0304050313267b38656531336535332d326331632d343262622d386466372d3339393237633062646262367d");
      assert.deepStrictEqual(name.toJSON(), [
        { "Email": ["some@email.com"] },
        { "IP": ["192.168.0.1"] },
        { "GUID": ["{8ee13e53-2c1c-42bb-8df7-39927c0bdbb6}"] },
      ]);
    });

  });

  context("Pkcs10CertificateRequest", () => {

    it("read", () => {
      const pem = "MIICdDCCAVwCAQAwLzEtMA8GA1UEAxMIdGVzdE5hbWUwGgYJKoZIhvcNAQkBEw10ZXN0QG1haWwubm90MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArut7tLrb1BEHXImMTWipet+3/J2isn7mBv278oP7YyOkmX/Vzxvk9nvSc/B1wh6kSo6nfaxYacNNSP3r+WQYaTeLm5TsDbUfCJYtvvTuYH0GVTM8Qm7QhMZKnyUy/D60WNcRM4pnBDSEMpKppi7HhfL37DZpQnsQfr9r8LQPWZ9t/mf+FsSeWyQOQcz+ob6cODfNQIvbzpaXXdNpKIHLPW+/e4af5/WlZ9wL5Sy7kOf4X6nErdl74s1vSji9goANSQkd5TbswtFPRNybikrrisz0HtsIq2uTGDY6t3iOEHTe5qe/ux4anjbSqKVuIQEQWQOKb4h+mHTc+EC5yknihQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE7TU20ui1MLtxLM0UZMytYAjC7vtXxB5Vl6bzHUzZkVFW6oTeizqDxjeBtZ1SqErpgdyvzMvFSxF6f+679kl1/Zs2V0IPa4y58he3wTT/M1xCBN/bITY2cA4ETozbtK4cGoi6jY/0j8NcxTLfiBgwhE3ap+9GzLtWEhHWCXmpsohbvAktXSh1tLh4xmgoQoePEBSPbnaOmsonyzscKiBMASDvjrFdNbtD0uY2v/wYXwtRGvV/Q/O3lLWEosE4NdnZmgId4bm7ru48WucSnxuEJAkKUjDLrN0uqY/tKfX4Zy9w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U=";
      const csr = new x509.Pkcs10CertificateRequest(Convert.FromBase64(pem));
      assert.strictEqual(csr.subject, "CN=testName+E=test@mail.not");
    });

    it("verify", async () => {
      const pem = "MIICRzCCAS8CAQAwAjEAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArut7tLrb1BEHXImMTWipet+3/J2isn7mBv278oP7YyOkmX/Vzxvk9nvSc/B1wh6kSo6nfaxYacNNSP3r+WQYaTeLm5TsDbUfCJYtvvTuYH0GVTM8Qm7QhMZKnyUy/D60WNcRM4pnBDSEMpKppi7HhfL37DZpQnsQfr9r8LQPWZ9t/mf+FsSeWyQOQcz+ob6cODfNQIvbzpaXXdNpKIHLPW+/e4af5/WlZ9wL5Sy7kOf4X6nErdl74s1vSji9goANSQkd5TbswtFPRNybikrrisz0HtsIq2uTGDY6t3iOEHTe5qe/ux4anjbSqKVuIQEQWQOKb4h+mHTc+EC5yknihQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE7TU20ui1MLtxLM0UZMytYAjC7vtXxB5Vl6bzHUzZkVFW6oTeizqDxjeBtZ1SqErpgdyvzMvFSxF6f+679kl1/Zs2V0IPa4y58he3wTT/M1xCBN/bITY2cA4ETozbtK4cGoi6jY/0j8NcxTLfiBgwhE3ap+9GzLtWEhHWCXmpsohbvAktXSh1tLh4xmgoQoePEBSPbnaOmsonyzscKiBMASDvjrFdNbtD0uY2v/wYXwtRGvV/Q/O3lLWEosE4NdnZmgId4bm7ru48WucSnxuEJAkKUjDLrN0uqY/tKfX4Zy9w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U=";
      const csr = new x509.Pkcs10CertificateRequest(Convert.FromBase64(pem));
      const ok = await csr.verify();
      assert.strictEqual(ok, true);
    });

  });

  context("Pkcs10CertificateRequestGenerator", () => {

    it("simple", async () => {
      const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]) as CryptoKeyPair;
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        keys,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      });

      assert(csr);
      assert.strictEqual(csr.subject, "");
      assert.deepStrictEqual(csr.attributes.length, 0);
      assert.deepStrictEqual(csr.extensions.length, 0);
      assert.deepStrictEqual(csr.signatureAlgorithm, { name: "ECDSA", hash: { name: "SHA-256" } });
      assert.deepStrictEqual(csr.publicKey.algorithm, { name: "ECDSA", namedCurve: "P-256" });
    });

    it("with attributes and extensions", async () => {
      const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, false, ["sign", "verify"]) as CryptoKeyPair;
      const csr = await x509.Pkcs10CertificateRequestGenerator.create({
        name: "CN=Test",
        keys,
        signingAlgorithm: { name: "ECDSA", hash: "SHA-384" },
        extensions: [
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
        ],
        attributes: [
          new x509.ChallengePasswordAttribute("password"),
        ]
      });

      assert(csr);
      assert.strictEqual(csr.subject, "CN=Test");
      assert.deepStrictEqual(csr.attributes.length, 2);
      assert.deepStrictEqual(csr.extensions.length, 1);
      assert.deepStrictEqual(csr.signatureAlgorithm, { name: "ECDSA", hash: { name: "SHA-384" } });
      assert.deepStrictEqual(csr.publicKey.algorithm, { name: "ECDSA", namedCurve: "P-384" });
    });
  });

  context("x509", () => {

    const pem = "MIIDljCCAn6gAwIBAgIOSETcxtRwD/qzf0FjVvEwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGjAYBgNVBAsTEUZvciBEZW1vIFVzZSBPbmx5MSAwHgYDVQQDExdHbG9iYWxTaWduIERlbW8gUm9vdCBDQTAeFw0xNjA3MjAwMDAwMDBaFw0zNjA3MjAwMDAwMDBaMGYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRowGAYDVQQLExFGb3IgRGVtbyBVc2UgT25seTEgMB4GA1UEAxMXR2xvYmFsU2lnbiBEZW1vIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1i9RNgrJ4YAATN0J4KVGZjFGQVGFdcbKvfxrt0Bfusq2g81iVrZZjqTJnPSx4g6TdVcsEXU9GWlkFXKEtZzYM4ycbwLAeJQxQDEqkV03GV8ks2Jq/6jIm2DbByPiS5fvRQFQJLYuQHqXpjpOpmPiostUsg9ydMEqcacYV22a6A6Nrb1c1B6OL+X0u9bo30K+YYSw2Ngp3Tuuj9PDk6JS/0CPLcLo8JIFFc8t78lPDquNAOqTDwY/HTw4751iqLVem9q3EDKEeUS+x4gqsCD2pENA7PlQBza55BGOi/A+UAsmfee1oq2Glo9buXBgX+oJ3HnyelzJU9Ej4+yfH7rcvAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTqD8ID9OxgG83HZJVtOQMmftrrLzANBgkqhkiG9w0BAQsFAAOCAQEAAECKKpL0A2I+hsY881tIz7WqkLDuLh/ISzRVdsALYAxLhVDUHPckh5XyVRkpbTmirn+b5MpuwAI2R8A7Ld6aWWiibc7zGEZNvEKsUEYoJoYR0fuQs2cF7egiYjhFwFMX75w+kuI0Yelm3/3+BiJVtAXqmnQ4yRpGXqNJ4mQC8yWgQbZCLUpH/nqeQANeoaDr5Yg8IOuHRQzG6YNt/Cl9CetDd8WPrAkGm3T2iG0dXQ48VgkkXcNDtY+55nYjIO+N7i+WTh1fe3ArGxHBR3E44+WoA8ntfI1g65+GR0s6G8M7oS+kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q==";

    it("read", () => {
      const cert = new x509.X509Certificate(Convert.FromBase64(pem));
      assert.strictEqual(cert.serialNumber, "4844dcc6d4700ffab37f416356f1");
      assert.strictEqual(cert.subject, "C=BE, O=GlobalSign nv-sa, OU=For Demo Use Only, CN=GlobalSign Demo Root CA");
      assert.strictEqual(cert.issuer, "C=BE, O=GlobalSign nv-sa, OU=For Demo Use Only, CN=GlobalSign Demo Root CA");
      assert.strictEqual(cert.extensions.length, 3);
    });

    it("verify", async () => {
      const cert = new x509.X509Certificate(Convert.FromBase64(pem));
      const ok = await cert.verify({ date: new Date(2020, 5, 7) });
      assert.strictEqual(ok, true);
    });

    context("thumbprint", () => {

      it("default", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const thumbprint = await cert.getThumbprint();
        assert.strictEqual(Convert.ToHex(thumbprint), "0cfbca8d79cdc989e4dd64abbc2f979cc9e0ccb4");
      });

      it("SHA-256", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const thumbprint = await cert.getThumbprint("SHA-256");
        assert.strictEqual(Convert.ToHex(thumbprint), "3578985ded3c684a00d138596cadc96a37eb2dd01511b4b7b7135a55362153df");
      });

      it("SHA-256, custom crypto", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const thumbprint = await cert.getThumbprint("SHA-256", crypto);
        assert.strictEqual(Convert.ToHex(thumbprint), "3578985ded3c684a00d138596cadc96a37eb2dd01511b4b7b7135a55362153df");
      });

      it("default algorithm, custom crypto", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const thumbprint = await cert.getThumbprint(crypto);
        assert.strictEqual(Convert.ToHex(thumbprint), "0cfbca8d79cdc989e4dd64abbc2f979cc9e0ccb4");
      });
    });

    context("getExtensions", () => {

      it("existing", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const extensions = cert.getExtensions("2.5.29.15");
        assert.strictEqual(extensions.length, 1);
        assert.strictEqual(extensions[0] instanceof x509.KeyUsagesExtension, true);
      });

      it("class", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const extensions = cert.getExtensions(x509.KeyUsagesExtension);
        assert.strictEqual(extensions.length, 1);
        assert.strictEqual(extensions[0] instanceof x509.KeyUsagesExtension, true);
      });

      it("null", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const extensions = cert.getExtensions("2.5.29.16");
        assert.strictEqual(extensions.length, 0);
      });

    });

    context("getExtension", () => {

      it("class", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const extension = cert.getExtension(x509.KeyUsagesExtension);
        assert(extension);
        assert.strictEqual(extension instanceof x509.KeyUsagesExtension, true);
      });

    });

    context("toString", () => {
      it("hex", () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const hex = cert.toString("hex");
        assert.strictEqual(hex, "308203963082027ea003020102020e4844dcc6d4700ffab37f416356f1300d06092a864886f70d01010b05003066310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361311a3018060355040b1311466f722044656d6f20557365204f6e6c793120301e06035504031317476c6f62616c5369676e2044656d6f20526f6f74204341301e170d3136303732303030303030305a170d3336303732303030303030305a3066310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361311a3018060355040b1311466f722044656d6f20557365204f6e6c793120301e06035504031317476c6f62616c5369676e2044656d6f20526f6f7420434130820122300d06092a864886f70d01010105000382010f003082010a0282010100b58bd44d82b2786000133742782951998c519054615d71b2af7f1aedd017eeb2ada0f35895ad9663a932673d2c7883a4dd55cb045d4f465a59055ca12d67360ce3271bc0b01e250c500c4aa4574dc657c92cd89abfea3226d836c1c8f892e5fbd14054092d8b901ea5e98e93a998f8a8b2d52c83dc9d304a9c69c615db66ba03a36b6f573507a38bf97d2ef5ba37d0af98612c36360a774eeba3f4f0e4e894bfd023cb70ba3c24814573cb7bf253c3aae3403aa4c3c18fc74f0e3be758aa2d57a6f6adc40ca11e512fb1e20aac083da910d03b3e5401cdae790463a2fc0f9402c99f79ed68ab61a5a3d6ee5c1817fa82771e7c9e973254f448f8fb27c7eeb72f0203010001a3423040300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414ea0fc203f4ec601bcdc764956d3903267edaeb2f300d06092a864886f70d01010b0500038201010000408a2a92f403623e86c63cf35b48cfb5aa90b0ee2e1fc84b345576c00b600c4b8550d41cf7248795f25519296d39a2ae7f9be4ca6ec0023647c03b2dde9a5968a26dcef318464dbc42ac504628268611d1fb90b36705ede822623845c05317ef9c3e92e23461e966dffdfe062255b405ea9a7438c91a465ea349e26402f325a041b6422d4a47fe7a9e40035ea1a0ebe5883c20eb87450cc6e9836dfc297d09eb4377c58fac09069b74f6886d1d5d0e3c5609245dc343b58fb9e6762320ef8dee2f964e1d5f7b702b1b11c1477138e3e5a803c9ed7c8d60eb9f86474b3a1bc33ba12fa40055c8c2e8141981274d6a749b96c09f93650f7d782043a0e269d2f1");
        const cert2 = new x509.X509Certificate(hex);
        assert.strictEqual(cert2.equal(cert), true);
      });
      it("pem", () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const pem2 = cert.toString("pem");
        assert.strictEqual(pem2, `-----BEGIN CERTIFICATE-----
MIIDljCCAn6gAwIBAgIOSETcxtRwD/qzf0FjVvEwDQYJKoZIhvcNAQELBQAwZjEL
MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGjAYBgNVBAsT
EUZvciBEZW1vIFVzZSBPbmx5MSAwHgYDVQQDExdHbG9iYWxTaWduIERlbW8gUm9v
dCBDQTAeFw0xNjA3MjAwMDAwMDBaFw0zNjA3MjAwMDAwMDBaMGYxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRowGAYDVQQLExFGb3IgRGVt
byBVc2UgT25seTEgMB4GA1UEAxMXR2xvYmFsU2lnbiBEZW1vIFJvb3QgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1i9RNgrJ4YAATN0J4KVGZjFGQ
VGFdcbKvfxrt0Bfusq2g81iVrZZjqTJnPSx4g6TdVcsEXU9GWlkFXKEtZzYM4ycb
wLAeJQxQDEqkV03GV8ks2Jq/6jIm2DbByPiS5fvRQFQJLYuQHqXpjpOpmPiostUs
g9ydMEqcacYV22a6A6Nrb1c1B6OL+X0u9bo30K+YYSw2Ngp3Tuuj9PDk6JS/0CPL
cLo8JIFFc8t78lPDquNAOqTDwY/HTw4751iqLVem9q3EDKEeUS+x4gqsCD2pENA7
PlQBza55BGOi/A+UAsmfee1oq2Glo9buXBgX+oJ3HnyelzJU9Ej4+yfH7rcvAgMB
AAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBTqD8ID9OxgG83HZJVtOQMmftrrLzANBgkqhkiG9w0BAQsFAAOCAQEAAECKKpL0
A2I+hsY881tIz7WqkLDuLh/ISzRVdsALYAxLhVDUHPckh5XyVRkpbTmirn+b5Mpu
wAI2R8A7Ld6aWWiibc7zGEZNvEKsUEYoJoYR0fuQs2cF7egiYjhFwFMX75w+kuI0
Yelm3/3+BiJVtAXqmnQ4yRpGXqNJ4mQC8yWgQbZCLUpH/nqeQANeoaDr5Yg8IOuH
RQzG6YNt/Cl9CetDd8WPrAkGm3T2iG0dXQ48VgkkXcNDtY+55nYjIO+N7i+WTh1f
e3ArGxHBR3E44+WoA8ntfI1g65+GR0s6G8M7oS+kAFXIwugUGYEnTWp0m5bAn5Nl
D314IEOg4mnS8Q==
-----END CERTIFICATE-----`);
        const cert2 = new x509.X509Certificate(pem2);
        assert.strictEqual(cert2.equal(cert), true);
      });
      it("base64", () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const base64 = cert.toString("base64");
        assert.strictEqual(base64, "MIIDljCCAn6gAwIBAgIOSETcxtRwD/qzf0FjVvEwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGjAYBgNVBAsTEUZvciBEZW1vIFVzZSBPbmx5MSAwHgYDVQQDExdHbG9iYWxTaWduIERlbW8gUm9vdCBDQTAeFw0xNjA3MjAwMDAwMDBaFw0zNjA3MjAwMDAwMDBaMGYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRowGAYDVQQLExFGb3IgRGVtbyBVc2UgT25seTEgMB4GA1UEAxMXR2xvYmFsU2lnbiBEZW1vIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1i9RNgrJ4YAATN0J4KVGZjFGQVGFdcbKvfxrt0Bfusq2g81iVrZZjqTJnPSx4g6TdVcsEXU9GWlkFXKEtZzYM4ycbwLAeJQxQDEqkV03GV8ks2Jq/6jIm2DbByPiS5fvRQFQJLYuQHqXpjpOpmPiostUsg9ydMEqcacYV22a6A6Nrb1c1B6OL+X0u9bo30K+YYSw2Ngp3Tuuj9PDk6JS/0CPLcLo8JIFFc8t78lPDquNAOqTDwY/HTw4751iqLVem9q3EDKEeUS+x4gqsCD2pENA7PlQBza55BGOi/A+UAsmfee1oq2Glo9buXBgX+oJ3HnyelzJU9Ej4+yfH7rcvAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTqD8ID9OxgG83HZJVtOQMmftrrLzANBgkqhkiG9w0BAQsFAAOCAQEAAECKKpL0A2I+hsY881tIz7WqkLDuLh/ISzRVdsALYAxLhVDUHPckh5XyVRkpbTmirn+b5MpuwAI2R8A7Ld6aWWiibc7zGEZNvEKsUEYoJoYR0fuQs2cF7egiYjhFwFMX75w+kuI0Yelm3/3+BiJVtAXqmnQ4yRpGXqNJ4mQC8yWgQbZCLUpH/nqeQANeoaDr5Yg8IOuHRQzG6YNt/Cl9CetDd8WPrAkGm3T2iG0dXQ48VgkkXcNDtY+55nYjIO+N7i+WTh1fe3ArGxHBR3E44+WoA8ntfI1g65+GR0s6G8M7oS+kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q==");
        const cert2 = new x509.X509Certificate(base64);
        assert.strictEqual(cert2.equal(cert), true);
      });
      it("base64url", () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const base64url = cert.toString("base64url");
        assert.strictEqual(base64url, "MIIDljCCAn6gAwIBAgIOSETcxtRwD_qzf0FjVvEwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGjAYBgNVBAsTEUZvciBEZW1vIFVzZSBPbmx5MSAwHgYDVQQDExdHbG9iYWxTaWduIERlbW8gUm9vdCBDQTAeFw0xNjA3MjAwMDAwMDBaFw0zNjA3MjAwMDAwMDBaMGYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRowGAYDVQQLExFGb3IgRGVtbyBVc2UgT25seTEgMB4GA1UEAxMXR2xvYmFsU2lnbiBEZW1vIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1i9RNgrJ4YAATN0J4KVGZjFGQVGFdcbKvfxrt0Bfusq2g81iVrZZjqTJnPSx4g6TdVcsEXU9GWlkFXKEtZzYM4ycbwLAeJQxQDEqkV03GV8ks2Jq_6jIm2DbByPiS5fvRQFQJLYuQHqXpjpOpmPiostUsg9ydMEqcacYV22a6A6Nrb1c1B6OL-X0u9bo30K-YYSw2Ngp3Tuuj9PDk6JS_0CPLcLo8JIFFc8t78lPDquNAOqTDwY_HTw4751iqLVem9q3EDKEeUS-x4gqsCD2pENA7PlQBza55BGOi_A-UAsmfee1oq2Glo9buXBgX-oJ3HnyelzJU9Ej4-yfH7rcvAgMBAAGjQjBAMA4GA1UdDwEB_wQEAwIBBjAPBgNVHRMBAf8EBTADAQH_MB0GA1UdDgQWBBTqD8ID9OxgG83HZJVtOQMmftrrLzANBgkqhkiG9w0BAQsFAAOCAQEAAECKKpL0A2I-hsY881tIz7WqkLDuLh_ISzRVdsALYAxLhVDUHPckh5XyVRkpbTmirn-b5MpuwAI2R8A7Ld6aWWiibc7zGEZNvEKsUEYoJoYR0fuQs2cF7egiYjhFwFMX75w-kuI0Yelm3_3-BiJVtAXqmnQ4yRpGXqNJ4mQC8yWgQbZCLUpH_nqeQANeoaDr5Yg8IOuHRQzG6YNt_Cl9CetDd8WPrAkGm3T2iG0dXQ48VgkkXcNDtY-55nYjIO-N7i-WTh1fe3ArGxHBR3E44-WoA8ntfI1g65-GR0s6G8M7oS-kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q");
        const cert2 = new x509.X509Certificate(base64url);
        assert.strictEqual(cert2.equal(cert), true);
      });
    });
  });

  context("PublicKey", () => {

    const spki = Convert.FromHex("30820122300d06092a864886f70d01010105000382010f003082010a0282010100a4737ac5ec77f06df3486264a3a17c783143e9023073af169cc245023b4711526b4a721832943bbb59be53d241f3203c1a5eac9e1d5bb57bc0644d943dd63525090a70e1484db4b5ac03185ee897ae8ebabf255ebfc77cfebec928ac0b1fceb33b60238ac2ba3f016c035a53a3011828c2e9bafdd7e2a797d94dcbd79ec54a5ae3c92abef565b2ea6bb4af89e2f7e4dd1b52978bb828cb44843ace8c9ad7f80bef7ffedc8b73a04b6ec44cd65fc6ba8fc216c6ca4bbc99677695439391a4d17893b8f54d6755b681210660f7865748fc1126e21e4d9cdcee436c3ce5ebd91912d08713cb91613ecde2e8af694daa27110b8d588f34e82e88aa56315d15428db90203010001");

    context("getThumbprint", () => {

      it("default", async () => {
        const key = new x509.PublicKey(spki);
        const thumbprint = await key.getThumbprint();
        assert.strictEqual(Convert.ToHex(thumbprint), "dd0137099d08ab3324e183ec258413d1b79e95b0");
      });

      it("SHA-256", async () => {
        const key = new x509.PublicKey(spki);
        const thumbprint = await key.getThumbprint("SHA-256");
        assert.strictEqual(Convert.ToHex(thumbprint), "5bdf9c42c2d13d8edfb7733c257f49ec7d8ac20d2dbe36a693e92b84a26c845c");
      });

      it("SHA-256, custom crypto", async () => {
        const key = new x509.PublicKey(spki);
        const thumbprint = await key.getThumbprint("SHA-256", crypto);
        assert.strictEqual(Convert.ToHex(thumbprint), "5bdf9c42c2d13d8edfb7733c257f49ec7d8ac20d2dbe36a693e92b84a26c845c");
      });

      it("default algorithm, custom crypto", async () => {
        const key = new x509.PublicKey(spki);
        const thumbprint = await key.getThumbprint(crypto);
        assert.strictEqual(Convert.ToHex(thumbprint), "dd0137099d08ab3324e183ec258413d1b79e95b0");
      });

    });

  });

  context("X509 certificate generator", () => {

    it("generate self-signed certificate", async () => {
      const alg: RsaHashedKeyGenParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
      };
      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]) as CryptoKeyPair;
      const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: "CN=Test",
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2020/01/02"),
        signingAlgorithm: alg,
        keys: keys,
        extensions: [
          new x509.BasicConstraintsExtension(true, 2, true),
          new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
          await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        ]
      });
      const ok = await cert.verify({ date: new Date("2020/01/01 12:00") });
      assert.strictEqual(ok, true);
    });

    it("generate ca and user certificate", async () => {
      const alg: EcdsaParams & EcKeyGenParams = {
        name: "ECDSA",
        hash: "SHA-256",
        namedCurve: "P-256",
      };
      const caKeys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]) as CryptoKeyPair;
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
      assert.strictEqual(ok, true);

      const userKeys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]) as CryptoKeyPair;
      const userCert = await x509.X509CertificateGenerator.create({
        serialNumber: "01",
        subject: "CN=Test",
        issuer: caCert.issuer,
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2020/01/02"),
        signingAlgorithm: alg,
        publicKey: userKeys.publicKey,
        signingKey: caKeys.privateKey,
      });

      ok = await userCert.verify({
        date: new Date("2020/01/01 12:00"),
        publicKey: await caCert.publicKey.export()
      });
      assert.strictEqual(ok, true);
    });

  });

  context("X509Certificates", () => {

    const certs: x509.X509Certificates = new x509.X509Certificates();

    before(async () => {
      const alg: EcKeyGenParams & EcdsaParams = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]) as CryptoKeyPair;
      certs.push(await x509.X509CertificateGenerator.createSelfSigned({
        name: "CN=Test #1",
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2020/02/01"),
        keys,
        serialNumber: "01",
        signingAlgorithm: alg,
      }));
      certs.push(await x509.X509CertificateGenerator.createSelfSigned({
        name: "CN=Test #2",
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2020/02/01"),
        keys,
        serialNumber: "02",
        signingAlgorithm: alg,
      }));
    });

    context("import/export", () => {
      it("raw", async () => {
        const raw = await certs.export("raw");
        assert.strictEqual(raw instanceof ArrayBuffer, true);
        const certs2 = new x509.X509Certificates(raw);

        assert.strictEqual(certs2.length, 2);
        assert.strictEqual(certs2[0].subject, "CN=Test #1");
        assert.strictEqual(certs2[1].subject, "CN=Test #2");
      });
      it("hex", async () => {
        const hex = await certs.export("hex");
        assert.strictEqual(Convert.isHex(hex), true);
        const certs2 = new x509.X509Certificates(hex);

        assert.strictEqual(certs2.length, 2);
        assert.strictEqual(certs2[0].subject, "CN=Test #1");
        assert.strictEqual(certs2[1].subject, "CN=Test #2");
      });
      it("pem", async () => {
        const pem = await certs.export("pem");
        assert.strictEqual(x509.PemConverter.isPem(pem), true);
        const certs2 = new x509.X509Certificates(pem);

        assert.strictEqual(certs2.length, 2);
        assert.strictEqual(certs2[0].subject, "CN=Test #1");
        assert.strictEqual(certs2[1].subject, "CN=Test #2");
      });
      it("base64", async () => {
        const base64 = await certs.export("base64");
        assert.strictEqual(Convert.isBase64(base64), true);
        const certs2 = new x509.X509Certificates(base64);

        assert.strictEqual(certs2.length, 2);
        assert.strictEqual(certs2[0].subject, "CN=Test #1");
        assert.strictEqual(certs2[1].subject, "CN=Test #2");
      });
      it("base64url", async () => {
        const base64url = await certs.export("base64url");
        assert.strictEqual(Convert.isBase64Url(base64url), true);
        const certs2 = new x509.X509Certificates(base64url);

        assert.strictEqual(certs2.length, 2);
        assert.strictEqual(certs2[0].subject, "CN=Test #1");
        assert.strictEqual(certs2[1].subject, "CN=Test #2");
      });
    });

  });

  context("chain", () => {

    const alg: RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };

    async function createCert(name: string, cert?: x509.X509Certificate, useKeyId = false) {
      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]) as CryptoKeyPair;

      const extensions: x509.Extension[] = [];
      const skiExt = await x509.SubjectKeyIdentifierExtension.create(keys.publicKey);
      extensions.push(skiExt);
      if (useKeyId) {
        const akiExt = await x509.AuthorityKeyIdentifierExtension.create(cert ? await cert.publicKey.export() : keys.publicKey);
        extensions.push(akiExt);
      }

      const res = await x509.X509CertificateGenerator.create({
        serialNumber: "01",
        subject: `CN=${name}`,
        issuer: cert ? cert.subject : `CN=${name}`,
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2020/01/02"),
        signingAlgorithm: alg,
        publicKey: keys.publicKey,
        signingKey: cert && cert.privateKey ? cert.privateKey : keys.privateKey,
        extensions,
      });
      res.privateKey = keys.privateKey;

      return res;
    }

    const certs = new x509.X509Certificates();

    before(async () => {
      certs.push(await createCert("Root CA")); // 0
      const root2 = await createCert("Root CA #2");
      certs.push(await createCert("Intermediate CA #1", certs[0], true)); // 1
      certs.push(await createCert("Intermediate CA #2", certs[0])); // 2
      certs.push(await createCert("Intermediate CA #1.1", certs[1], true)); // 3
      certs.push(await createCert("Intermediate CA #2.1", certs[2])); // 4
      certs.push(await createCert("Intermediate CA #1.1.1", certs[3], true)); // 5
      certs.push(await createCert("Client #1", certs[5], true)); // 6
      certs.push(await createCert("Client #2", certs[4])); // 7
      certs.push(await createCert("Odd cert", undefined, true)); // 8
      certs.push(await createCert("Intermediate CA #3", root2, true)); // 9
      certs.push(await createCert("Intermediate CA #3.1", certs[9], true)); // 10
      certs.push(await createCert("User #3.1.1", certs[10], true)); // 11
      certs.push(await createCert("Root CA #3")); // 12
      certs.push(await createCert("Intermediate CA same name")); // 13
      certs.push(await createCert("Intermediate CA same name", certs[12])); // 14
      certs.push(await createCert("Client same name", certs[14])); // 15
    });

    it("without key identifiers", async () => {
      const chain = new x509.X509ChainBuilder({
        certificates: certs,
      });
      const items = await chain.build(certs[7]);
      assert.strictEqual(items.length, 4);
      assert.strictEqual(items.map(o => o.subject).join(","), "CN=Client #2,CN=Intermediate CA #2.1,CN=Intermediate CA #2,CN=Root CA");
    });

    it("with key identifiers", async () => {
      const chain = new x509.X509ChainBuilder({
        certificates: certs,
      });
      const items = await chain.build(certs[6]);
      assert.strictEqual(items.length, 5);
      assert.strictEqual(items.map(o => o.subject).join(","), "CN=Client #1,CN=Intermediate CA #1.1.1,CN=Intermediate CA #1.1,CN=Intermediate CA #1,CN=Root CA");
    });

    it("uncompleted path", async () => {
      const chain = new x509.X509ChainBuilder({
        certificates: certs,
      });
      const items = await chain.build(certs[11]);
      assert.strictEqual(items.length, 3);
      assert.strictEqual(items.map(o => o.subject).join(","), "CN=User #3.1.1,CN=Intermediate CA #3.1,CN=Intermediate CA #3");
    });

    it("single cert", async () => {
      const chain = new x509.X509ChainBuilder({
        certificates: certs,
      });
      const items = await chain.build(certs[8]);
      assert.strictEqual(items.length, 1);
      assert.strictEqual(items.map(o => o.subject).join(","), "CN=Odd cert");
    });

    it("self-signed cert", async () => {
      const chain = new x509.X509ChainBuilder({
        certificates: certs,
      });
      const items = await chain.build(certs[0]);
      assert.strictEqual(items.length, 1);
      assert.strictEqual(items.map(o => o.subject).join(","), "CN=Root CA");
    });

    it("ca with the same name and serial number (without kid)", async () => {
      const chain = new x509.X509ChainBuilder({
        certificates: certs,
      });
      const items = await chain.build(certs[15]);
      assert.strictEqual(items.length, 3);
      assert.strictEqual(items.map(o => o.subject).join(","), "CN=Client same name,CN=Intermediate CA same name,CN=Root CA #3");
    });

  });

  context("Extensions", () => {

    it("Subject Alternative Name", () => {
      const hex = "3081a80603551d110481a030819d820d736f6d652e6e616d652e636f6d820e736f6d65322e6e616d652e636f6d81126d6963726f7368696e65406d61696c2e7275a01f06092b0601040182371901a0120410533ee18e1c2cbb428df739927c0bdbb687040a0109058613687474703a2f2f736f6d652e75726c2e636f6d861666696c653a2f2f2f736f6d652f66696c652f70617468a014060a2b060104018237140203a0060c0475736572";
      const san = new x509.SubjectAlternativeNameExtension(Convert.FromHex(hex));
      const json = san.toJSON();
      assert.deepStrictEqual(json, {
        dns: ["some.name.com", "some2.name.com"],
        email: ["microshine@mail.ru"],
        ip: ["10.1.9.5"],
        guid: ["{8ee13e53-2c1c-42bb-8df7-39927c0bdbb6}"],
        upn: ["user"],
        url: ["http://some.url.com", "file:///some/file/path"]
      });

      const san2 = new x509.SubjectAlternativeNameExtension(json, san.critical);
      const hex2 = Convert.ToHex(san2.rawData);

      assert.strictEqual(hex2, hex);
    });

  });

  context("issues", () => {

    it("#5 verification failing for x509 certificate with ECDSA", async () => {
      const ca = new x509.X509Certificate("MIICVzCCAf2gAwIBAgIUH5dl9HNmcklznEOCTZxFIN65ugYwCgYIKoZIzj0EAwIwdTELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRAwDgYDVQQHEwdSYWxlaWdoMQ0wCwYDVQQKEwRFREpYMRUwEwYDVQQLEwxFREpYIFJvb3QgQ0ExFTATBgNVBAMTDEVESlggUm9vdCBDQTAeFw0yMTAxMDcwNzE2MDBaFw0yNDAxMDcwNzE2MDBaMH0xCzAJBgNVBAYTAlVTMRcwFQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEQMA4GA1UEBxMHUmFsZWlnaDENMAsGA1UEChMERURKWDEVMBMGA1UECxMMRURKWCBSb290IENBMR0wGwYDVQQDExRFREpYIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCDz/PG5Nw0Q45Vafk3p3RABsaiGgv5FPFEl+jfVVxw6o084dU+GibHJqL9JOk9t7zaXdc04oQSy0dkviV40HQGjYzBhMA4GA1UdDwEB/wQEAwICBDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSQcYOQauj7nFQP4ZWKp59JtGVZajAfBgNVHSMEGDAWgBQU/uYHGGZLCS8dm9tCcaSBodnGnTAKBggqhkjOPQQDAgNIADBFAiEAgiDUpS14LEn9p/2u93L8+PsfvUHVD2WItO6cPfTT01cCIDr/RT6K5CmGnGgmFRrn/hZyGe3CvpzKfZqMX63UeoQQ");
      const leaf = new x509.X509Certificate("MIICgzCCAimgAwIBAgIUU3QVClDwfllZDosbQuijZEqeqN0wCgYIKoZIzj0EAwIwfTELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRAwDgYDVQQHEwdSYWxlaWdoMQ0wCwYDVQQKEwRFREpYMRUwEwYDVQQLEwxFREpYIFJvb3QgQ0ExHTAbBgNVBAMTFEVESlggSW50ZXJtZWRpYXRlIENBMB4XDTIxMDEwNzA3MTYwMFoXDTIyMDEwNzA3MTYwMFowaTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk5DMRAwDgYDVQQHEwdSZWxlaWdoMQ0wCwYDVQQKEwRFREpYMRQwEgYDVQQLEwtFbmdpbmVlcmluZzEWMBQGA1UEAxMNYXBpLmVkangudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKZwl6VQ9VZHpelF+ZhBkKY3N7f7qXvvIwDBIDpV18+iYs1r01Qoo2TwJh3/j/n87sqtm4nfuOBvjL8M/RUdDRWjgZowgZcwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQjjloUw1goFcY26GEIxnJlckH+JTAfBgNVHSMEGDAWgBSQcYOQauj7nFQP4ZWKp59JtGVZajAYBgNVHREEETAPgg1hcGkuZWRqeC50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIFYIeb08ZaNS6iFPrOdhCAZW10XF4C2oT9GwOMJ8tKp8AiEA25uqFuewgI0SuLTWX6MGa1pd9z0p2Ks+8/+1pY9PUGc=");
      const ok = await leaf.verify({
        signatureOnly: true,
        publicKey: ca,
      });
      assert.strictEqual(ok, true);
    });

  });

});