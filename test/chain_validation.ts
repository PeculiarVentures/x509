import { Crypto } from "@peculiar/webcrypto";
import {
  describe, it, expect,
} from "vitest";
import {
  X509CertificateGenerator,
  X509ChainBuilder,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  cryptoProvider,
} from "../src";

// Set crypto provider if not already set (though the library might do it)
if (!cryptoProvider.get()) {
  cryptoProvider.set(new Crypto());
}

describe("X509ChainBuilder Security", () => {
  it("should NOT build a chain using a non-CA certificate as an issuer", async () => {
    const crypto = cryptoProvider.get();

    console.log("Generating Root CA...");
    const rootAlg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
    const rootKeys = await crypto.subtle.generateKey(rootAlg, true, ["sign", "verify"]);
    const rootCert = await X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=Root CA",
      notBefore: new Date("2020/01/01"),
      notAfter: new Date("2030/01/01"),
      signingAlgorithm: rootAlg,
      keys: rootKeys,
      extensions: [
        new BasicConstraintsExtension(true, undefined, true), // CA=true
        new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
      ],
    });

    console.log("Generating End Entity (EE) certificate (NOT a CA)...");
    const eeAlg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
    const eeKeys = await crypto.subtle.generateKey(eeAlg, true, ["sign", "verify"]);
    const eeCert = await X509CertificateGenerator.create({
      serialNumber: "02",
      subject: "CN=End Entity",
      issuer: "CN=Root CA",
      notBefore: new Date("2020/01/01"),
      notAfter: new Date("2030/01/01"),
      signingAlgorithm: rootAlg,
      signingKey: rootKeys.privateKey,
      publicKey: eeKeys.publicKey,
      extensions: [
        new BasicConstraintsExtension(false, undefined, true), // CA=false
        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true), // No keyCertSign
      ],
    });

    console.log("Generating Fake Certificate signed by EE (which should NOT be allowed)...");
    const fakeAlg = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };
    const fakeKeys = await crypto.subtle.generateKey(fakeAlg, true, ["sign", "verify"]);
    const fakeCert = await X509CertificateGenerator.create({
      serialNumber: "03",
      subject: "CN=Fake Cert",
      issuer: "CN=End Entity",
      notBefore: new Date("2020/01/01"),
      notAfter: new Date("2030/01/01"),
      signingAlgorithm: eeAlg,
      signingKey: eeKeys.privateKey,
      publicKey: fakeKeys.publicKey,
      extensions: [
        new BasicConstraintsExtension(false, undefined, true),
      ],
    });

    console.log("Building chain for Fake Cert...");
    const chainBuilder = new X509ChainBuilder({ certificates: [rootCert, eeCert] });

    const chain = await chainBuilder.build(fakeCert);
    console.log("Chain built successfully (length):", chain.length);
    for (const cert of chain) {
      console.log(" - " + cert.subject);
    }

    // We expect the chain building to FAIL or at least NOT include the EE cert as a CA.
    // However, since X509ChainBuilder might just follow signatures, it likely builds it.
    // If it builds a chain of length 3 (Fake -> EE -> Root), it confirms the vulnerability
    // in the context of "validating certificate chains".

    // If the chain is built, we assert that we consider this a failure of the "Chain Builder"
    // to enforce basic constraints.
    expect(chain.length).not.toBe(3);
  });
});
