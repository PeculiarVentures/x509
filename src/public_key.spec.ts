import { describe, it, expect, beforeAll } from "vitest";
import type { IPublicKeyContainer } from "./index";
import { CryptoProvider, PublicKey, cryptoProvider } from "./index";
import { hex, toArrayBuffer } from "@peculiar/utils";
import * as x509 from "./index";

describe("PublicKey", () => {
  let crypto: globalThis.Crypto;
  let cryptoKey: CryptoKey;
  let spki: BufferSource;

  beforeAll(async () => {
    crypto = cryptoProvider.get();
    const alg = {
      name: "ECDSA",
      namedCurve: "P-256",
    };
    const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    cryptoKey = keys.publicKey;
    spki = await crypto.subtle.exportKey("spki", keys.publicKey);
  });

  describe("create", () => {
    it("should create an instance from PublicKey", async () => {
      const publicKey = new PublicKey(spki);
      const result = await PublicKey.create(publicKey);
      expect(result instanceof PublicKey).toBeTruthy();
    });

    it("should create an instance from CryptoKey", async () => {
      const result = await PublicKey.create(cryptoKey);
      expect(result instanceof PublicKey).toBeTruthy();
    });

    it("should create an instance from IPublicKeyContainer", async () => {
      const publicKey = new PublicKey(spki);
      const container: IPublicKeyContainer = { publicKey };
      const result = await PublicKey.create(container);
      expect(result instanceof PublicKey).toBeTruthy();
    });

    it("should create an instance from BufferSource", async () => {
      const result = await PublicKey.create(spki);
      expect(result instanceof PublicKey).toBeTruthy();
    });

    it("should throw an error for unsupported type", async () => {
      const promise = PublicKey.create("test" as any);
      await expect(promise).rejects.toThrow(TypeError);
    });
  });

  describe("export", () => {
    it("should export a public CryptoKey", async () => {
      const publicKey = new PublicKey(spki);
      const key = await publicKey.export();
      expect(CryptoProvider.isCryptoKey(key)).toBeTruthy();
    });
  });

  describe("getThumbprint", () => {
    it("should return a SHA-1 thumbprint", async () => {
      const publicKey = await PublicKey.create(spki);
      const thumbprint = await publicKey.getThumbprint();
      expect(thumbprint.byteLength).toBe(20);
    });

    it("should return a thumbprint for specified algorithm", async () => {
      const publicKey = await PublicKey.create(spki);
      const thumbprint = await publicKey.getThumbprint("SHA-256");
      expect(thumbprint.byteLength).toBe(32);
    });
  });

  describe("getKeyIdentifier", () => {
    it("should return a key identifier", async () => {
      const publicKey = await PublicKey.create(spki);
      const keyIdentifier = await publicKey.getKeyIdentifier();
      expect(keyIdentifier.byteLength).toBe(20);
    });

    it("should return a key identifier for specified algorithm", async () => {
      const publicKey = await PublicKey.create(spki);
      const keyIdentifier = await publicKey.getKeyIdentifier("SHA-256");
      expect(keyIdentifier.byteLength).toBe(32);
    });

    it("should return a key identifier for specified algorithm and crypto provider", async () => {
      // A provider other than the default one
      const crypto = globalThis.crypto;
      const publicKey = await PublicKey.create(spki);
      const keyIdentifier = await publicKey.getKeyIdentifier("SHA-256", crypto);
      expect(keyIdentifier.byteLength).toBe(32);
    });
  });
});

describe("crypto", () => {
  const crypto = x509.cryptoProvider.get();

  describe("PublicKey", () => {
    const spki = toArrayBuffer(
      hex.decode(
        "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a4737ac5ec77f06df3486264a3a17c783143e9023073af169cc245023b4711526b4a721832943bbb59be53d241f3203c1a5eac9e1d5bb57bc0644d943dd63525090a70e1484db4b5ac03185ee897ae8ebabf255ebfc77cfebec928ac0b1fceb33b60238ac2ba3f016c035a53a3011828c2e9bafdd7e2a797d94dcbd79ec54a5ae3c92abef565b2ea6bb4af89e2f7e4dd1b52978bb828cb44843ace8c9ad7f80bef7ffedc8b73a04b6ec44cd65fc6ba8fc216c6ca4bbc99677695439391a4d17893b8f54d6755b681210660f7865748fc1126e21e4d9cdcee436c3ce5ebd91912d08713cb91613ecde2e8af694daa27110b8d588f34e82e88aa56315d15428db90203010001",
      ),
    );

    describe("export", () => {
      it("with RSA-PSS algorithm", async () => {
        // RSA-PSS algorithm is not supported for SPKI in browsers
        // x509 module reconverts it to RSA-PKCS1
        const b64 =
          "MIIBUzA+BgkqhkiG9w0BAQowMaANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgGiBAICAN4DggEPADCCAQoCggEBANbStMMWVHrgQgc1DZ4nr2XegPv069OhV0uiMwgM7QzvPot1TmCH4biJ/YMrBN9IY+hwGT30wSUkp0/EruMducqUQ/jy3zf/7KHqZnHOi7LDPdan3JvoJQrdY0BeMcdVFfvLP7S9Jfpd7ZM90h7oof+JcaMhoJWPNEH92a1viwFcw9t+wruK15/mftnmdgbWpFmDvK14YDz6hVWQ4lQyvS0HYHO4KCX+H7vb2gl0u1gDslrS1At5ky9OLs3l6QZ5AHP9Qxzh7HWnBaqupuD/n12umE4nlNE5GZegFWjhcwHgZ4pl7Q7QQnMRK86D6T5I88/10iFR66nMGZ+Y/lwyGM8CAwEAAQ==";
        const key = new x509.PublicKey(b64);
        const cryptoKey = await key.export();
        expect(cryptoKey.type).toBe("public");
      });
    });
    describe("getThumbprint", () => {
      it("default", async () => {
        const key = new x509.PublicKey(spki);
        const thumbprint = await key.getThumbprint();
        expect(hex.encode(thumbprint)).toBe("dd0137099d08ab3324e183ec258413d1b79e95b0");
      });

      it("SHA-256", async () => {
        const key = new x509.PublicKey(spki);
        const thumbprint = await key.getThumbprint("SHA-256");
        expect(hex.encode(thumbprint)).toBe("5bdf9c42c2d13d8edfb7733c257f49ec7d8ac20d2dbe36a693e92b84a26c845c");
      });

      it("SHA-256, custom crypto", async () => {
        const key = new x509.PublicKey(spki);
        const thumbprint = await key.getThumbprint("SHA-256", crypto);
        expect(hex.encode(thumbprint)).toBe("5bdf9c42c2d13d8edfb7733c257f49ec7d8ac20d2dbe36a693e92b84a26c845c");
      });

      it("default algorithm, custom crypto", async () => {
        const key = new x509.PublicKey(spki);
        const thumbprint = await key.getThumbprint(crypto);
        expect(hex.encode(thumbprint)).toBe("dd0137099d08ab3324e183ec258413d1b79e95b0");
      });
    });
  });
});
