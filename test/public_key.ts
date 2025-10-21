import {
  describe, it, expect, beforeAll,
} from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import {
  CryptoProvider, IPublicKeyContainer, PublicKey, cryptoProvider,
} from "../src";

describe("PublicKey", () => {
  let crypto: globalThis.Crypto;
  let cryptoKey: CryptoKey;
  let spki: BufferSource;

  beforeAll(async () => {
    crypto = cryptoProvider.get();
    const alg = {
      name: "ECDSA", namedCurve: "P-256",
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
      const crypto = new Crypto();
      const publicKey = await PublicKey.create(spki);
      const keyIdentifier = await publicKey.getKeyIdentifier("SHA-256", crypto);
      expect(keyIdentifier.byteLength).toBe(32);
    });
  });
});
