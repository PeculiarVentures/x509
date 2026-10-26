import { describe, it, expect, beforeAll } from "vitest";
import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificateList } from "@peculiar/asn1-x509";
import * as x509 from "./index";
import { base64, toArrayBuffer } from "@peculiar/utils";

const crypto = x509.cryptoProvider.get();

describe("X509Crl", () => {
  let keys: CryptoKeyPair;
  let crl: x509.X509Crl;
  const alg = {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  };
  const issuerName = "CN=Test CA, O=Test Org";
  const thisUpdate = new Date("2023-01-01T00:00:00Z");
  const nextUpdate = new Date("2023-01-08T00:00:00Z");
  const revokedSerial = "010203";
  const revocationDate = new Date("2023-01-02T00:00:00Z");

  beforeAll(async () => {
    keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

    crl = await x509.X509CrlGenerator.create({
      issuer: issuerName,
      thisUpdate,
      nextUpdate,
      signingAlgorithm: alg,
      signingKey: keys.privateKey,
      entries: [
        {
          serialNumber: revokedSerial,
          revocationDate,
          reason: x509.X509CrlReason.keyCompromise,
          invalidity: new Date("2023-01-01T12:00:00Z"),
        },
        {
          serialNumber: "040506", // Entry without optional fields
          revocationDate: new Date("2023-01-03T00:00:00Z"),
        },
      ],
      extensions: [
        new x509.BasicConstraintsExtension(true), // Just using some extension for testing
      ],
    });
  });

  it("should parse properties correctly", () => {
    expect(crl).toBeDefined();
    expect(crl.version).toBe(1); // v2
    expect(crl.issuer).toBe(issuerName);
    expect(crl.thisUpdate.getTime()).toBe(thisUpdate.getTime());
    expect(crl.nextUpdate?.getTime()).toBe(nextUpdate.getTime());
    expect(crl.signatureAlgorithm.name).toBe("ECDSA");
    expect(crl.signature).toBeDefined();
  });

  it("should have correct entries", () => {
    expect(crl.entries.length).toBe(2);

    const entry1 = crl.entries[0];
    expect(entry1.serialNumber).toBe(revokedSerial);
    expect(entry1.revocationDate.getTime()).toBe(revocationDate.getTime());
    expect(entry1.reason).toBe(x509.X509CrlReason.keyCompromise);
    expect(entry1.invalidity?.getTime()).toBe(new Date("2023-01-01T12:00:00Z").getTime());

    const entry2 = crl.entries[1];
    expect(entry2.serialNumber).toBe("040506");
    expect(entry2.reason).toBeUndefined();
    expect(entry2.invalidity).toBeUndefined();
  });

  it("should handle extensions", () => {
    expect(crl.extensions.length).toBeGreaterThan(0);
    const ext = crl.getExtension<x509.BasicConstraintsExtension>("2.5.29.19");
    expect(ext).toBeDefined();
    // Use 'ca' not 'cA'
    expect(ext?.ca).toBe(true);

    const extByType = crl.getExtension(x509.BasicConstraintsExtension);
    expect(extByType).toBeDefined();
    expect(extByType?.ca).toBe(true);

    const exts = crl.getExtensions("2.5.29.19");
    expect(exts.length).toBe(1);

    const extsByType = crl.getExtensions(x509.BasicConstraintsExtension);
    expect(extsByType.length).toBe(1);
  });

  it("should verify signature with CryptoKey", async () => {
    const ok = await crl.verify({ publicKey: keys.publicKey });
    expect(ok).toBe(true);
  });

  it("should verify signature with PublicKey", async () => {
    const spki = await crypto.subtle.exportKey("spki", keys.publicKey);
    const publicKey = new x509.PublicKey(spki);
    const ok = await crl.verify({ publicKey });
    expect(ok).toBe(true);
  });

  it("should verify signature with X509Certificate", async () => {
    // Generate a self-signed cert with the same key
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      keys,
      name: issuerName,
      signingAlgorithm: alg,
      notBefore: thisUpdate,
      notAfter: nextUpdate,
    });

    const ok = await crl.verify({ publicKey: cert });
    expect(ok).toBe(true);
  });

  it("should fail verification with wrong key", async () => {
    const newKeys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    const ok = await crl.verify({ publicKey: newKeys.publicKey });
    expect(ok).toBe(false);
  });

  it("should find revoked certificate", () => {
    const entry = crl.findRevoked(revokedSerial);
    expect(entry).toBeDefined();
    expect(entry?.serialNumber).toBe(revokedSerial);

    const entryByCert = crl.findRevoked({ serialNumber: revokedSerial } as x509.X509Certificate);
    expect(entryByCert).toBeDefined();
    expect(entryByCert?.serialNumber).toBe(revokedSerial);

    const notFound = crl.findRevoked("000000");
    expect(notFound).toBeNull();
  });

  it("should get thumbprint", async () => {
    const thumbprint = await crl.getThumbprint();
    expect(thumbprint.byteLength).toBe(20); // SHA-1

    const thumbprint256 = await crl.getThumbprint("SHA-256");
    expect(thumbprint256.byteLength).toBe(32);
  });

  it("should construct from PEM", () => {
    const pem = crl.toString("pem");
    const crlFromPem = new x509.X509Crl(pem);
    expect(crlFromPem.issuer).toBe(crl.issuer);
  });

  it("should throw on creation with invalid args", () => {
    // Use an invalid string that looks somewhat like a string but isn't a valid format
    expect(() => new x509.X509Crl("invalid string")).toThrow();
  });
});

describe("X509CrlGenerator", () => {
  let keys: CryptoKeyPair;
  const alg = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
  };

  beforeAll(async () => {
    keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  });

  it("should create CRL with RSA key", async () => {
    const crl = await x509.X509CrlGenerator.create({
      issuer: "CN=RSA CA",
      signingAlgorithm: alg,
      signingKey: keys.privateKey,
      entries: [
        {
          serialNumber: "1234",
          revocationDate: new Date(),
        },
      ],
    });

    expect(crl).toBeDefined();
    expect(crl.signatureAlgorithm.name).toBe("RSASSA-PKCS1-v1_5");
    const ok = await crl.verify({ publicKey: keys.publicKey });
    expect(ok).toBe(true);
  });

  it("should throw if duplicate entries", async () => {
    await expect(
      x509.X509CrlGenerator.create({
        issuer: "CN=Test",
        signingAlgorithm: alg,
        signingKey: keys.privateKey,
        entries: [
          {
            serialNumber: "01",
            revocationDate: new Date(),
          },
          {
            serialNumber: "01",
            revocationDate: new Date(),
          },
        ],
      }),
    ).rejects.toThrow("already exists");
  });

  // First byte 0xf6 has the high bit set; without sign-padding this would be
  // encoded as a negative DER INTEGER (RFC 5280 §4.1.2.2 violation).
  const highBitSerial = "f6f3c85e97e433070c51e0527b20b7f4";

  it("should encode a high-bit-set serial number as a positive INTEGER", async () => {
    const crl = await x509.X509CrlGenerator.create({
      issuer: "CN=Test CA",
      thisUpdate: new Date(),
      nextUpdate: new Date(),
      signingAlgorithm: alg,
      signingKey: keys.privateKey,
      entries: [
        {
          serialNumber: highBitSerial,
          revocationDate: new Date(),
        },
      ],
    });

    // Inspect the raw DER INTEGER content octets directly: the getter strips
    // the sign-pad, so assert on the encoding rather than on serialNumber.
    const asn = AsnConvert.parse(crl.rawData, CertificateList);
    const revoked = asn.tbsCertList.revokedCertificates ?? [];
    const userCertificate = new Uint8Array(revoked[0].userCertificate);
    expect(userCertificate[0]).toBe(0x00); // leading sign-pad byte => positive INTEGER
  });

  it("should expose the serial number consistently with X509Certificate", async () => {
    const crl = await x509.X509CrlGenerator.create({
      issuer: "CN=Test CA",
      thisUpdate: new Date(),
      nextUpdate: new Date(),
      signingAlgorithm: alg,
      signingKey: keys.privateKey,
      entries: [
        {
          serialNumber: highBitSerial,
          revocationDate: new Date(),
        },
      ],
    });

    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: highBitSerial,
      name: "CN=Test CA",
      notBefore: new Date("2020-01-01"),
      notAfter: new Date("2060-01-01"),
      signingAlgorithm: alg,
      keys,
    });

    const parsed = new x509.X509Crl(crl.rawData);
    const entry = parsed.findRevoked(highBitSerial);
    expect(entry).not.toBeNull();
    // The CRL entry getter strips the sign-pad, matching X509Certificate.
    expect(entry?.serialNumber).toBe(highBitSerial);
    expect(entry?.serialNumber).toBe(cert.serialNumber);
  });

  it.each(["", "00", "0000"])("should keep the zero serial number %j as given", async (serialNumber) => {
    const crl = await x509.X509CrlGenerator.create({
      issuer: "CN=Test CA",
      thisUpdate: new Date(),
      nextUpdate: new Date(),
      signingAlgorithm: alg,
      signingKey: keys.privateKey,
      entries: [
        {
          serialNumber,
          revocationDate: new Date(),
        },
      ],
    });

    // The serial number must be normalized, not replaced by a random one.
    const parsed = new x509.X509Crl(crl.rawData);
    expect(parsed.entries.length).toBe(1);
    expect(parsed.entries[0].serialNumber).toBe("00");
    expect(parsed.findRevoked(serialNumber)?.serialNumber).toBe("00");
  });

  it("should throw if duplicate entries with zero serial numbers", async () => {
    await expect(
      x509.X509CrlGenerator.create({
        issuer: "CN=Test CA",
        thisUpdate: new Date(),
        nextUpdate: new Date(),
        signingAlgorithm: alg,
        signingKey: keys.privateKey,
        entries: [
          {
            serialNumber: "00",
            revocationDate: new Date(),
          },
          {
            serialNumber: "0000",
            revocationDate: new Date(),
          },
        ],
      }),
    ).rejects.toThrow("already exists");
  });
});

describe("X509CrlEntry", () => {
  it("should normalize the serial number", () => {
    // High bit set, so the serial number gets a sign-pad byte on encoding, and
    // the getter strips it again.
    const entry = new x509.X509CrlEntry("f6f3c8", new Date(), []);
    expect(entry.serialNumber).toBe("f6f3c8");

    // Zero serial numbers must be normalized, not replaced by a random one.
    const zeroEntry = new x509.X509CrlEntry("0000", new Date(), []);
    expect(zeroEntry.serialNumber).toBe("00");
  });
});

describe("crypto", () => {
  describe("X509Crl", () => {
    const pem =
      "MIICADCB6QIBATANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBDQRcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBEMCACAQ4XDTEwMDEwMTA4MzAwMFowDDAKBgNVHRUEAwoBATAgAgEPFw0xMDAxMDEwODMwMDFaMAwwCgYDVR0VBAMKAQGgLzAtMB8GA1UdIwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1rzrJMAoGA1UdFAQDAgEBMA0GCSqGSIb3DQEBCwUAA4IBAQA9vPMLiinD8G7FaoTsu8T2jUrTi1OLPHxKnrlBrAP/eHa+VQV1HJfY5Gjq1dpNgzZqDIgQM5QHPm0aSgMN7Ultx+XzbxRswLnwgQrZ7f76Tlky1I+jz7/p3AEynrNR72v64SZt46UhpSuWBHoF1uEVtgirTZNfOEaGUJTNOaTA5U55/iw9BKjHN0e/Vd7OGnrk5h6FsgWOiasGn6/tym9teDt/L2hlOdsZsvX1KPc0ExUHVjJIUBYTooqyy/CuTzFHla6RYVYvJuRF5qYCxa0GTZK3ImCtJ3XfsGdfLEJDZ7T17xBQHucMvIVLm6vY44WUy7PqQhZJskhJMEvj01ZE";

    it("read", () => {
      const crl = new x509.X509Crl(toArrayBuffer(base64.decode(pem)));
      expect(crl.issuer).toBe("C=US, O=Test Certificates 2011, CN=Good CA");
      expect(crl.extensions.length).toBe(2);
    });

    it("verify", async () => {
      const goodCACert =
        "MIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3QgQW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMTB0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37Xfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXaBGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47RuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHnUGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+VmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9yrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7mtvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCuFMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FGQYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzP=";
      const badCACert =
        "MIIDijCCAnKgAwIBAgIBETANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMEMxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMRMwEQYDVQQDEwpHb29kIHN1YkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsg6YlsgUI+JxeULQ+eIB+57x/d39rz5zlcqfjzxk95+il+BC1o3VuwtIIxYMSNmi/5GvBuGLtjA0/XLCvM9GnONzZhmBUGU6voomA7W/WFZAqi7cDNEEzT9E7oJAoiQBNXPXngmJX8OLG9yLMOTolFlLoUvmAoDGryln42gYcYXdJMoWCq+JkAaxs4tVCl+OkAfLRM7yh/IZrhjfeQpMcy01e+Oku2AqdJTQSDjDBrvI21+rB3LnjJvWbpm7NbJL35LmOc/kd2YPyFw4vJ0uFdn95lKEuM6HY/PtkJNr36/qwJ0ixntXPCyYLyDSFqaSa+9LGbcJrp6yRoCD4hcZOwIDAQABo4GLMIGIMB8GA1UdIwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1rzrJMB0GA1UdDgQWBBQyByyedF0tXSm7sXqNOxVStH1CeDAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDAYDVR0kBAUwA4ABADANBgkqhkiG9w0BAQsFAAOCAQEAcX2vRsH1O1HQsB/7Jlf+ov4pfIwfT5PAvv+p4bo+wWcumPIC1DjUk8xnOQUz3RkhQyqTbE+1OGuA1fjO0VJZ7YevKlO6MHkMYT4N5mge2ZuxMW+35ohZ23DHEHGk174QY6V8l4ICau2s1/SRajFqfRmY3s8gZFo0UBX0KIcmXSu0YHfaHWXnq7bs8kCODW0qMQnlpsUtbwdlPn5jt1kbMnRkrKzjruehXGm7gXC2QlHgH/MfJgpawne/n0DwPBVMs/KVuR/HRadunSuGf5Vy/rm6kZ8Lnu8+sk3pfWXdwEK2tWArcVUv3wh6jROOasEQC1Ah3H0iXv/ETCv3BnBHFc==";

      const cert = new x509.X509Certificate(toArrayBuffer(base64.decode(goodCACert)));
      const crl = new x509.X509Crl(toArrayBuffer(base64.decode(pem)));

      const ok = await crl.verify({ publicKey: cert });
      expect(ok).toBe(true);

      const cert2 = new x509.X509Certificate(toArrayBuffer(base64.decode(badCACert)));
      const error = await crl.verify({ publicKey: cert2 });
      expect(error).toBe(false);
    });

    it("findRevoked", () => {
      const crl = new x509.X509Crl(toArrayBuffer(base64.decode(pem)));
      const entry = crl.findRevoked("0e");
      expect(entry && entry.serialNumber).toBe("0e");
      expect(entry && entry.revocationDate).toEqual(new Date("2010-01-01T08:30:00.000Z"));
      expect(entry && entry.extensions.length).toBe(1);

      const entry2 = crl.findRevoked("1");
      expect(entry2).toBe(null);
    });
  });
});
