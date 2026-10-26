import { describe, it, expect, beforeAll } from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import * as x509 from "./index";

describe("crypto", () => {
  const crypto = new Crypto();
  x509.cryptoProvider.set(crypto);

  describe("chain", () => {
    const alg: RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-384",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };

    async function createCert(name: string, cert?: x509.X509Certificate, useKeyId = false) {
      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
      expect(keys.publicKey).toBeTruthy();
      expect(keys.privateKey).toBeTruthy();

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

    beforeAll(async () => {
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
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[7]);
      expect(items.length).toBe(4);
      expect(items.map((o) => o.subject).join(",")).toBe("CN=Client #2,CN=Intermediate CA #2.1,CN=Intermediate CA #2,CN=Root CA");
    });

    it("with key identifiers", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[6]);
      expect(items.length).toBe(5);
      expect(items.map((o) => o.subject).join(",")).toBe("CN=Client #1,CN=Intermediate CA #1.1.1,CN=Intermediate CA #1.1,CN=Intermediate CA #1,CN=Root CA");
    });

    it("uncompleted path", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[11]);
      expect(items.length).toBe(3);
      expect(items.map((o) => o.subject).join(",")).toBe("CN=User #3.1.1,CN=Intermediate CA #3.1,CN=Intermediate CA #3");
    });

    it("single cert", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[8]);
      expect(items.length).toBe(1);
      expect(items.map((o) => o.subject).join(", ")).toBe("CN=Odd cert");
    });

    it("self-signed cert", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[0]);
      expect(items.length).toBe(1);
      expect(items.map((o) => o.subject).join(", ")).toBe("CN=Root CA");
    });

    it("ca with the same name and serial number (without kid)", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[15]);
      expect(items.length).toBe(3);
      expect(items.map((o) => o.subject).join(",")).toBe("CN=Client same name,CN=Intermediate CA same name,CN=Root CA #3");
    });
  });
});
