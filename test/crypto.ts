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

    it("import/export", async () => {
      const raw = await certs.export();
      const certs2 = new x509.X509Certificates(raw);

      assert.strictEqual(certs2.length, 2);
      assert.strictEqual(certs2[0].subject, "CN=Test #1");
      assert.strictEqual(certs2[1].subject, "CN=Test #2");
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

});