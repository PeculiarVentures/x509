import * as path from "path";
import {
  describe, it, expect, beforeAll,
} from "vitest";
import { Crypto } from "@peculiar/webcrypto";
import * as x509 from "../src";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

describe(path.basename(__filename), () => {
  let keys: CryptoKeyPair;
  const alg = {
    name: "ECDSA",
    hash: "SHA-256",
    namedCurve: "P-256",
  };

  beforeAll(async () => {
    keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  });

  describe("create", () => {
    it("should throw error on duplicate serial numbers", async () => {
      const serialNumber = "010203";

      await expect(
        x509.X509CrlGenerator.create({
          issuer: "CN=Test CA",
          thisUpdate: new Date(),
          signingAlgorithm: alg,
          signingKey: keys.privateKey,
          entries: [
            {
              serialNumber,
              revocationDate: new Date(),
            },
            {
              serialNumber,
              revocationDate: new Date(),
            },
          ],
        }),
      ).rejects.toThrow(`Certificate serial number ${serialNumber} already exists in tbsCertList`);
    });
  });
});
