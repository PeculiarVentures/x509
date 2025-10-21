import {
  describe, it, expect, beforeEach,
} from "vitest";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import {
  ECParameters, id_ecPublicKey, id_secp256r1,
} from "@peculiar/asn1-ecc";
import { AsnConvert } from "@peculiar/asn1-schema";
import { EcAlgorithm, HashedAlgorithm } from "../src";

describe("EcAlgorithm", () => {
  let ecAlgorithm: EcAlgorithm;

  beforeEach(() => {
    ecAlgorithm = new EcAlgorithm();
  });

  const testVectors: {
    asnAlgorithm: string;
    webAlgorithm: HashedAlgorithm | EcKeyGenParams;
  }[] = [
    {
      asnAlgorithm: "1.2.840.10045.4.1",
      webAlgorithm: {
        name: "ECDSA", hash: { name: "SHA-1" },
      },
    },
    {
      asnAlgorithm: "1.2.840.10045.4.3.2",
      webAlgorithm: {
        name: "ECDSA", hash: { name: "SHA-256" },
      },
    },
    {
      asnAlgorithm: "1.2.840.10045.4.3.3",
      webAlgorithm: {
        name: "ECDSA", hash: { name: "SHA-384" },
      },
    },
    {
      asnAlgorithm: "1.2.840.10045.4.3.4",
      webAlgorithm: {
        name: "ECDSA", hash: { name: "SHA-512" },
      },
    },
    {
      asnAlgorithm: id_secp256r1,
      webAlgorithm: {
        name: "ECDSA", namedCurve: "P-256",
      },
    },
    {
      asnAlgorithm: "1.3.132.0.10",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "K-256",
      },
    },
    {
      asnAlgorithm: "1.3.132.0.34",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "P-384",
      },
    },
    {
      asnAlgorithm: "1.3.132.0.35",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "P-521",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.1",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP160r1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.2",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP160t1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.3",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP192r1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.4",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP192t1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.5",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP224r1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.6",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP224t1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.7",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP256r1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.8",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP256t1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.9",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP320r1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.10",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP320t1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.11",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP384r1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.12",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP384t1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.13",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP512r1",
      },
    },
    {
      asnAlgorithm: "1.3.36.3.3.2.8.1.1.14",
      webAlgorithm: {
        name: "ECDSA", namedCurve: "brainpoolP512t1",
      },
    },
  ];

  testVectors.forEach(({ asnAlgorithm, webAlgorithm }) => {
    const withValue = "hash" in webAlgorithm ? webAlgorithm.hash.name : webAlgorithm.namedCurve;

    describe(`Algorithm ${webAlgorithm.name} with ${withValue}`, () => {
      it("#toAsnAlgorithm()", () => {
        const result = ecAlgorithm.toAsnAlgorithm(webAlgorithm);
        expect(result).toBeTruthy();
        if (result) {
          if ("hash" in webAlgorithm) {
            expect(result.algorithm).toBe(asnAlgorithm);
          } else {
            expect(result.algorithm).toBe(id_ecPublicKey);
            expect(result.parameters).toBeTruthy();
            if (result.parameters) {
              const asnParameters = AsnConvert.parse(result.parameters, ECParameters);
              expect(asnParameters.namedCurve).toBe(asnAlgorithm);
            }
          }
        }
      });

      it("#toWebAlgorithm()", () => {
        const algIdentifier = "hash" in webAlgorithm
          ? new AlgorithmIdentifier({ algorithm: asnAlgorithm })
          : new AlgorithmIdentifier({
              algorithm: id_ecPublicKey,
              parameters: AsnConvert.serialize(new ECParameters({ namedCurve: asnAlgorithm })),
            });
        const result = ecAlgorithm.toWebAlgorithm(algIdentifier);
        expect(result).toBeTruthy();
        expect(result).toEqual(webAlgorithm);
      });
    });
  });
});
