import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import * as asn1Ecc from "@peculiar/asn1-ecc";
import { container, injectable, diAlgorithm } from "./container";
import { AsnConvert } from "@peculiar/asn1-schema";
import { IAlgorithm } from "./algorithm";
import { HashedAlgorithm } from "./types";

const idVersionOne = "1.3.36.3.3.2.8.1.1";
/**
 * ```
 * brainpoolP160r1 OBJECT IDENTIFIER ::= { versionOne 1 }
 * ```
 */
const idBrainpoolP160r1 = `${idVersionOne}.1`;
/**
 * ```
 * brainpoolP160t1 OBJECT IDENTIFIER ::= { versionOne 2 }
 * ```
 */
const idBrainpoolP160t1 = `${idVersionOne}.2`;
/**
 * ```
 * brainpoolP192r1 OBJECT IDENTIFIER ::= { versionOne 3 }
 * ```
 */
const idBrainpoolP192r1 = `${idVersionOne}.3`;
/**
 * ```
 * brainpoolP192t1 OBJECT IDENTIFIER ::= { versionOne 4 }
 * ```
 */
const idBrainpoolP192t1 = `${idVersionOne}.4`;
/**
 * ```
 * brainpoolP224r1 OBJECT IDENTIFIER ::= { versionOne 5 }
 * ```
 */
const idBrainpoolP224r1 = `${idVersionOne}.5`;
/**
 * ```
 * brainpoolP224t1 OBJECT IDENTIFIER ::= { versionOne 6 }
 * ```
 */
const idBrainpoolP224t1 = `${idVersionOne}.6`;
/**
 * ```
 * brainpoolP256r1 OBJECT IDENTIFIER ::= { versionOne 7 }
 * ```
 */
const idBrainpoolP256r1 = `${idVersionOne}.7`;
/**
 * ```
 * brainpoolP256t1 OBJECT IDENTIFIER ::= { versionOne 8 }
 * ```
 */
const idBrainpoolP256t1 = `${idVersionOne}.8`;
/**
 * ```
 * brainpoolP320r1 OBJECT IDENTIFIER ::= { versionOne 9 }
 * ```
 */
const idBrainpoolP320r1 = `${idVersionOne}.9`;
/**
 * ```
 * brainpoolP320t1 OBJECT IDENTIFIER ::= { versionOne 10 }
 * ```
 */
const idBrainpoolP320t1 = `${idVersionOne}.10`;
/**
 * ```
 * brainpoolP384r1 OBJECT IDENTIFIER ::= { versionOne 11 }
 * ```
 */
const idBrainpoolP384r1 = `${idVersionOne}.11`;
/**
 * ```
 * brainpoolP384t1 OBJECT IDENTIFIER ::= { versionOne 12 }
 * ```
 */
const idBrainpoolP384t1 = `${idVersionOne}.12`;
/**
 * ```
 * brainpoolP512r1 OBJECT IDENTIFIER ::= { versionOne 13 }
 * ```
 */
const idBrainpoolP512r1 = `${idVersionOne}.13`;
/**
 * ```
 * brainpoolP512t1 OBJECT IDENTIFIER ::= { versionOne 14 }
 * ```
 */
const idBrainpoolP512t1 = `${idVersionOne}.14`;

const brainpoolP160r1 = "brainpoolP160r1";
const brainpoolP160t1 = "brainpoolP160t1";
const brainpoolP192r1 = "brainpoolP192r1";
const brainpoolP192t1 = "brainpoolP192t1";
const brainpoolP224r1 = "brainpoolP224r1";
const brainpoolP224t1 = "brainpoolP224t1";
const brainpoolP256r1 = "brainpoolP256r1";
const brainpoolP256t1 = "brainpoolP256t1";
const brainpoolP320r1 = "brainpoolP320r1";
const brainpoolP320t1 = "brainpoolP320t1";
const brainpoolP384r1 = "brainpoolP384r1";
const brainpoolP384t1 = "brainpoolP384t1";
const brainpoolP512r1 = "brainpoolP512r1";
const brainpoolP512t1 = "brainpoolP512t1";

const ECDSA = "ECDSA";
/**
 * EC algorithm provider
 */
@injectable()
export class EcAlgorithm implements IAlgorithm {
  public static SECP256K1 = "1.3.132.0.10";

  public toAsnAlgorithm(alg: HashedAlgorithm | EcKeyGenParams): AlgorithmIdentifier | null {
    switch (alg.name.toLowerCase()) {
      case ECDSA.toLowerCase():
        if ("hash" in alg) {
          const hash = typeof alg.hash === "string" ? alg.hash : alg.hash.name;
          switch (hash.toLowerCase()) {
            case "sha-1":
              return asn1Ecc.ecdsaWithSHA1;
            case "sha-256":
              return asn1Ecc.ecdsaWithSHA256;
            case "sha-384":
              return asn1Ecc.ecdsaWithSHA384;
            case "sha-512":
              return asn1Ecc.ecdsaWithSHA512;
          }
        } else if ("namedCurve" in alg) {
          let parameters = "";
          switch (alg.namedCurve) {
            case "P-256":
              parameters = asn1Ecc.id_secp256r1;
              break;
            case "K-256":
              parameters = EcAlgorithm.SECP256K1;
              break;
            case "P-384":
              parameters = asn1Ecc.id_secp384r1;
              break;
            case "P-521":
              parameters = asn1Ecc.id_secp521r1;
              break;
            case brainpoolP160r1:
              parameters = idBrainpoolP160r1;
              break;
            case brainpoolP160t1:
              parameters = idBrainpoolP160t1;
              break;
            case brainpoolP192r1:
              parameters = idBrainpoolP192r1;
              break;
            case brainpoolP192t1:
              parameters = idBrainpoolP192t1;
              break;
            case brainpoolP224r1:
              parameters = idBrainpoolP224r1;
              break;
            case brainpoolP224t1:
              parameters = idBrainpoolP224t1;
              break;
            case brainpoolP256r1:
              parameters = idBrainpoolP256r1;
              break;
            case brainpoolP256t1:
              parameters = idBrainpoolP256t1;
              break;
            case brainpoolP320r1:
              parameters = idBrainpoolP320r1;
              break;
            case brainpoolP320t1:
              parameters = idBrainpoolP320t1;
              break;
            case brainpoolP384r1:
              parameters = idBrainpoolP384r1;
              break;
            case brainpoolP384t1:
              parameters = idBrainpoolP384t1;
              break;
            case brainpoolP512r1:
              parameters = idBrainpoolP512r1;
              break;
            case brainpoolP512t1:
              parameters = idBrainpoolP512t1;
              break;
          }
          if (parameters) {
            return new AlgorithmIdentifier({
              algorithm: asn1Ecc.id_ecPublicKey,
              parameters: AsnConvert.serialize(
                new asn1Ecc.ECParameters({ namedCurve: parameters }),
              ),
            });
          }
        }
    }

    return null;
  }

  public toWebAlgorithm(alg: AlgorithmIdentifier): HashedAlgorithm | EcKeyGenParams | null {
    switch (alg.algorithm) {
      case asn1Ecc.id_ecdsaWithSHA1:
        return {
          name: ECDSA, hash: { name: "SHA-1" },
        };
      case asn1Ecc.id_ecdsaWithSHA256:
        return {
          name: ECDSA, hash: { name: "SHA-256" },
        };
      case asn1Ecc.id_ecdsaWithSHA384:
        return {
          name: ECDSA, hash: { name: "SHA-384" },
        };
      case asn1Ecc.id_ecdsaWithSHA512:
        return {
          name: ECDSA, hash: { name: "SHA-512" },
        };
      case asn1Ecc.id_ecPublicKey: {
        if (!alg.parameters) {
          throw new TypeError("Cannot get required parameters from EC algorithm");
        }
        const parameters = AsnConvert.parse(alg.parameters, asn1Ecc.ECParameters);
        switch (parameters.namedCurve) {
          case asn1Ecc.id_secp256r1:
            return {
              name: ECDSA, namedCurve: "P-256",
            };
          case EcAlgorithm.SECP256K1:
            return {
              name: ECDSA, namedCurve: "K-256",
            };
          case asn1Ecc.id_secp384r1:
            return {
              name: ECDSA, namedCurve: "P-384",
            };
          case asn1Ecc.id_secp521r1:
            return {
              name: ECDSA, namedCurve: "P-521",
            };
          case idBrainpoolP160r1:
            return {
              name: ECDSA, namedCurve: brainpoolP160r1,
            };
          case idBrainpoolP160t1:
            return {
              name: ECDSA, namedCurve: brainpoolP160t1,
            };
          case idBrainpoolP192r1:
            return {
              name: ECDSA, namedCurve: brainpoolP192r1,
            };
          case idBrainpoolP192t1:
            return {
              name: ECDSA, namedCurve: brainpoolP192t1,
            };
          case idBrainpoolP224r1:
            return {
              name: ECDSA, namedCurve: brainpoolP224r1,
            };
          case idBrainpoolP224t1:
            return {
              name: ECDSA, namedCurve: brainpoolP224t1,
            };
          case idBrainpoolP256r1:
            return {
              name: ECDSA, namedCurve: brainpoolP256r1,
            };
          case idBrainpoolP256t1:
            return {
              name: ECDSA, namedCurve: brainpoolP256t1,
            };
          case idBrainpoolP320r1:
            return {
              name: ECDSA, namedCurve: brainpoolP320r1,
            };
          case idBrainpoolP320t1:
            return {
              name: ECDSA, namedCurve: brainpoolP320t1,
            };
          case idBrainpoolP384r1:
            return {
              name: ECDSA, namedCurve: brainpoolP384r1,
            };
          case idBrainpoolP384t1:
            return {
              name: ECDSA, namedCurve: brainpoolP384t1,
            };
          case idBrainpoolP512r1:
            return {
              name: ECDSA, namedCurve: brainpoolP512r1,
            };
          case idBrainpoolP512t1:
            return {
              name: ECDSA, namedCurve: brainpoolP512t1,
            };
        }
      }
    }

    return null;
  }
}

// register EC algorithm provider as a singleton object
container.registerSingleton(diAlgorithm, EcAlgorithm);
