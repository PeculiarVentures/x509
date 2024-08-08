import * as assert from "node:assert";
import { Crypto } from "@peculiar/webcrypto";
import { CryptoProvider, IPublicKeyContainer, PublicKey, cryptoProvider } from "../src";

describe("PublicKey", () => {
  let crypto: Crypto;
  let cryptoKey: CryptoKey;
  let spki: BufferSource;

  before(async () => {
    crypto = cryptoProvider.get();
    const alg = { name: "ECDSA", namedCurve: "P-256" };
    const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
    cryptoKey = keys.publicKey;
    spki = await crypto.subtle.exportKey("spki", keys.publicKey);
  });

  describe("create", () => {
    it("should create an instance from PublicKey", async () => {
      const publicKey = new PublicKey(spki);
      const result = await PublicKey.create(publicKey);
      assert(result instanceof PublicKey);
    });

    it("should create an instance from CryptoKey", async () => {
      const result = await PublicKey.create(cryptoKey);
      assert(result instanceof PublicKey);
    });

    it("should create an instance from IPublicKeyContainer", async () => {
      const publicKey = new PublicKey(spki);
      const container: IPublicKeyContainer = { publicKey };
      const result = await PublicKey.create(container);
      assert(result instanceof PublicKey);
    });

    it("should create an instance from BufferSource", async () => {
      const result = await PublicKey.create(spki);
      assert(result instanceof PublicKey);
    });

    it("should throw an error for unsupported type", async () => {
      const promise = PublicKey.create("test" as any);
      await assert.rejects(promise, TypeError);
    });
  });

  describe("export", () => {
    it("should export a public CryptoKey", async () => {
      const publicKey = new PublicKey(spki);
      const key = await publicKey.export();
      assert.ok(CryptoProvider.isCryptoKey(key));
    });
  });

  describe("getThumbprint", () => {
    it("should return a SHA-1 thumbprint", async () => {
      const publicKey = await PublicKey.create(spki);
      const thumbprint = await publicKey.getThumbprint();
      assert.strictEqual(thumbprint.byteLength, 20);
    });

    it("should return a thumbprint for specified algorithm", async () => {
      const publicKey = await PublicKey.create(spki);
      const thumbprint = await publicKey.getThumbprint("SHA-256");
      assert.strictEqual(thumbprint.byteLength, 32);
    });
  });

  describe("getKeyIdentifier", () => {
    it("should return a key identifier", async () => {
      const publicKey = await PublicKey.create(spki);
      const keyIdentifier = await publicKey.getKeyIdentifier();
      assert.strictEqual(keyIdentifier.byteLength, 20);
    });

    it("should return a key identifier for specified algorithm", async () => {
      const publicKey = await PublicKey.create(spki);
      const keyIdentifier = await publicKey.getKeyIdentifier("SHA-256");
      assert.strictEqual(keyIdentifier.byteLength, 32);
    });

    it("should return a key identifier for specified algorithm and crypto provider", async () => {
      const crypto = new Crypto();
      const publicKey = await PublicKey.create(spki);
      const keyIdentifier = await publicKey.getKeyIdentifier("SHA-256", crypto);
      assert.strictEqual(keyIdentifier.byteLength, 32);
    });
  });
});