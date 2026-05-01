import {
  describe, it, expect, beforeAll,
} from "vitest";
import { container } from "tsyringe";
import {
  id_ml_dsa_44,
  id_ml_dsa_65,
  id_ml_dsa_87,
  id_slh_dsa_sha2_128s,
  id_slh_dsa_sha2_128f,
  id_slh_dsa_sha2_192s,
  id_slh_dsa_sha2_192f,
  id_slh_dsa_sha2_256s,
  id_slh_dsa_sha2_256f,
  id_slh_dsa_shake_128s,
  id_slh_dsa_shake_128f,
  id_slh_dsa_shake_192s,
  id_slh_dsa_shake_192f,
  id_slh_dsa_shake_256s,
  id_slh_dsa_shake_256f,
} from "@peculiar/asn1-x509-post-quantum";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { AlgorithmProvider, diAlgorithmProvider } from "../src";

describe("ML-DSA + SLH-DSA AlgorithmProvider wiring (FIPS 204 / FIPS 205)", () => {
  let algorithmProvider: AlgorithmProvider;

  beforeAll(() => {
    algorithmProvider = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
  });

  // Each row: [WebCrypto name, NIST CSOR OID constant, OID string]
  const mlDsaVectors: readonly [string, string][] = [
    ["ML-DSA-44", id_ml_dsa_44],
    ["ML-DSA-65", id_ml_dsa_65],
    ["ML-DSA-87", id_ml_dsa_87],
  ];

  const slhDsaVectors: readonly [string, string][] = [
    ["SLH-DSA-SHA2-128s", id_slh_dsa_sha2_128s],
    ["SLH-DSA-SHA2-128f", id_slh_dsa_sha2_128f],
    ["SLH-DSA-SHA2-192s", id_slh_dsa_sha2_192s],
    ["SLH-DSA-SHA2-192f", id_slh_dsa_sha2_192f],
    ["SLH-DSA-SHA2-256s", id_slh_dsa_sha2_256s],
    ["SLH-DSA-SHA2-256f", id_slh_dsa_sha2_256f],
    ["SLH-DSA-SHAKE-128s", id_slh_dsa_shake_128s],
    ["SLH-DSA-SHAKE-128f", id_slh_dsa_shake_128f],
    ["SLH-DSA-SHAKE-192s", id_slh_dsa_shake_192s],
    ["SLH-DSA-SHAKE-192f", id_slh_dsa_shake_192f],
    ["SLH-DSA-SHAKE-256s", id_slh_dsa_shake_256s],
    ["SLH-DSA-SHAKE-256f", id_slh_dsa_shake_256f],
  ];

  describe("ML-DSA (FIPS 204)", () => {
    for (const [name, oid] of mlDsaVectors) {
      it(`${name} → ${oid} with absent parameters`, () => {
        const asn = algorithmProvider.toAsnAlgorithm({ name } as Algorithm);
        expect(asn.algorithm).toBe(oid);
        expect(asn.parameters).toBe(undefined);
      });

      it(`${oid} → { name: "${name}" }`, () => {
        const web = algorithmProvider.toWebAlgorithm(new AlgorithmIdentifier({ algorithm: oid }));
        expect(web).toEqual({ name });
      });

      it(`${name} name lookup is case-insensitive`, () => {
        const asn = algorithmProvider.toAsnAlgorithm({ name: name.toLowerCase() } as Algorithm);
        expect(asn.algorithm).toBe(oid);
      });
    }
  });

  describe("SLH-DSA (FIPS 205)", () => {
    for (const [name, oid] of slhDsaVectors) {
      it(`${name} → ${oid} with absent parameters`, () => {
        const asn = algorithmProvider.toAsnAlgorithm({ name } as Algorithm);
        expect(asn.algorithm).toBe(oid);
        expect(asn.parameters).toBe(undefined);
      });

      it(`${oid} → { name: "${name}" }`, () => {
        const web = algorithmProvider.toWebAlgorithm(new AlgorithmIdentifier({ algorithm: oid }));
        expect(web).toEqual({ name });
      });

      it(`${name} name lookup is case-insensitive`, () => {
        const asn = algorithmProvider.toAsnAlgorithm({ name: name.toLowerCase() } as Algorithm);
        expect(asn.algorithm).toBe(oid);
      });
    }
  });
});
