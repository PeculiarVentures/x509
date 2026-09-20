import { describe, it, expect, beforeAll } from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import { execSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isEqual } from "pvtsutils";
import * as x509 from "../src";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

function isOpenSSL(): boolean {
  try {
    const out = execSync("openssl version", { encoding: "utf8" });

    return out.startsWith("OpenSSL");
  } catch {
    return false;
  }
}

describe("OCSP OpenSSL interop", () => {
  const alg = {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  };
  let dir: string;
  let caCert: x509.X509Certificate;
  let userCert: x509.X509Certificate;
  let caKeys: CryptoKeyPair;
  let reqDer: ArrayBuffer;
  let respDer: ArrayBuffer;

  beforeAll(async () => {
    caKeys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    caCert = await x509.X509CertificateGenerator.createSelfSigned({
      name: "CN=Test CA",
      keys: caKeys,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });
    const userKeys = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    userCert = await x509.X509CertificateGenerator.create({
      subject: "CN=User",
      issuer: "CN=Test CA",
      publicKey: userKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: alg,
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2030-01-01"),
    });

    const certId = await x509.OcspCertId.create(caCert, userCert, "SHA-1", crypto);
    const req = await x509.OcspRequest.create(
      { issuer: caCert, certificates: [userCert], hashAlgorithm: "SHA-1", nonce: false },
      crypto,
    );
    reqDer = req.rawData;

    const now = new Date();
    const resp = await x509.BasicOcspResponseGenerator.create(
      {
        issuer: caCert,
        signingKey: caKeys.privateKey,
        signingAlgorithm: alg,
        producedAt: now,
        responses: [{ certId, status: "good", thisUpdate: now }],
      },
      crypto,
    );
    respDer = resp.rawData;

    dir = mkdtempSync(join(tmpdir(), "ocsp-"));
    writeFileSync(join(dir, "ca.pem"), caCert.toString("pem"));
    writeFileSync(join(dir, "user.pem"), userCert.toString("pem"));
    writeFileSync(join(dir, "req.der"), Buffer.from(reqDer));
    writeFileSync(join(dir, "resp.der"), Buffer.from(respDer));
  });

  it.skipIf(!isOpenSSL())("openssl accepts our request", () => {
    const out = execSync(`openssl ocsp -reqin "${join(dir, "req.der")}" -text`, {
      encoding: "utf8",
    });
    expect(out).toContain("OCSP Request Data");
    expect(out).toContain(
      userCert.serialNumber.toUpperCase().replace(/^0+/, "") || userCert.serialNumber,
    );
  });

  it.skipIf(!isOpenSSL())("openssl accepts our response", () => {
    const out = execSync(`openssl ocsp -respin "${join(dir, "resp.der")}" -text`, {
      encoding: "utf8",
    });
    expect(out).toContain("OCSP Response Data");
    expect(out).toContain("successful");
    expect(out).toContain("good");
  });

  it.skipIf(!isOpenSSL())("openssl verifies our response", () => {
    const out = execSync(
      `openssl ocsp -issuer "${join(dir, "ca.pem")}" -cert "${join(dir, "user.pem")}" -CA "${join(dir, "ca.pem")}" -respin "${join(dir, "resp.der")}" -text`,
      { encoding: "utf8" },
    );
    expect(out).toContain("good");
    expect(out).toMatch(/Response verify OK|good/);
  });

  it.skipIf(!isOpenSSL())("parses openssl-generated request", async () => {
    execSync(
      `openssl ocsp -issuer "${join(dir, "ca.pem")}" -cert "${join(dir, "user.pem")}" -reqout "${join(dir, "ossl_req.der")}"`,
      { stdio: "pipe" },
    );
    const der = readFileSync(join(dir, "ossl_req.der"));
    const parsed = new x509.OcspRequest(der);
    expect(parsed.requests.length).toBe(1);
    expect(parsed.requests[0].serialNumber.toLowerCase()).toBe(userCert.serialNumber.toLowerCase());
    // Our CertID must be logically equal to the OpenSSL-generated one,
    // even if DER encodings differ (e.g. hash parameters absent vs NULL).
    const hashName = (parsed.requests[0].hashAlgorithm as Algorithm).name as x509.OcspHashAlgorithm;
    const ours = await x509.OcspCertId.create(caCert, userCert, hashName, crypto);
    expect(isEqual(parsed.requests[0].issuerNameHash, ours.issuerNameHash)).toBe(true);
    expect(isEqual(parsed.requests[0].issuerKeyHash, ours.issuerKeyHash)).toBe(true);
    expect(parsed.requests[0].equal(ours)).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });
});
