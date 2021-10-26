import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { asn1 } from "webcrypto-core";
import * as asn1Ecc from "@peculiar/asn1-ecc";
import { container, injectable } from "tsyringe";
import { diAlgorithm, IAlgorithm } from "./algorithm";
import { HashedAlgorithm } from "./types";
import { AsnConvert } from "@peculiar/asn1-schema";

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
              parameters = asn1.idBrainpoolP160r1;
              break;
            case brainpoolP160t1:
              parameters = asn1.idBrainpoolP160t1;
              break;
            case brainpoolP192r1:
              parameters = asn1.idBrainpoolP192r1;
              break;
            case brainpoolP192t1:
              parameters = asn1.idBrainpoolP192t1;
              break;
            case brainpoolP224r1:
              parameters = asn1.idBrainpoolP224r1;
              break;
            case brainpoolP224t1:
              parameters = asn1.idBrainpoolP224t1;
              break;
            case brainpoolP256r1:
              parameters = asn1.idBrainpoolP256r1;
              break;
            case brainpoolP256t1:
              parameters = asn1.idBrainpoolP256t1;
              break;
            case brainpoolP320r1:
              parameters = asn1.idBrainpoolP320r1;
              break;
            case brainpoolP320t1:
              parameters = asn1.idBrainpoolP320t1;
              break;
            case brainpoolP384r1:
              parameters = asn1.idBrainpoolP384r1;
              break;
            case brainpoolP384t1:
              parameters = asn1.idBrainpoolP384t1;
              break;
            case brainpoolP512r1:
              parameters = asn1.idBrainpoolP512r1;
              break;
            case brainpoolP512t1:
              parameters = asn1.idBrainpoolP512t1;
              break;
          }
          if (parameters) {
            return new AlgorithmIdentifier({
              algorithm: asn1Ecc.id_ecPublicKey,
              parameters: AsnConvert.serialize(new asn1Ecc.ECParameters({ namedCurve: parameters })),
            });
          }
        }
    }

    return null;
  }

  public toWebAlgorithm(alg: AlgorithmIdentifier): HashedAlgorithm | EcKeyGenParams | null {
    switch (alg.algorithm) {
      case asn1Ecc.id_ecdsaWithSHA1:
        return { name: ECDSA, hash: { name: "SHA-1" } };
      case asn1Ecc.id_ecdsaWithSHA256:
        return { name: ECDSA, hash: { name: "SHA-256" } };
      case asn1Ecc.id_ecdsaWithSHA384:
        return { name: ECDSA, hash: { name: "SHA-384" } };
      case asn1Ecc.id_ecdsaWithSHA512:
        return { name: ECDSA, hash: { name: "SHA-512" } };
      case asn1Ecc.id_ecPublicKey: {
        if (!alg.parameters) {
          throw new TypeError("Cannot get required parameters from EC algorithm");
        }
        const parameters = AsnConvert.parse(alg.parameters, asn1Ecc.ECParameters);
        switch (parameters.namedCurve) {
          case asn1Ecc.id_secp256r1:
            return { name: ECDSA, namedCurve: "P-256" };
          case EcAlgorithm.SECP256K1:
            return { name: ECDSA, namedCurve: "K-256" };
          case asn1Ecc.id_secp384r1:
            return { name: ECDSA, namedCurve: "P-384" };
          case asn1Ecc.id_secp521r1:
            return { name: ECDSA, namedCurve: "P-521" };
          case asn1.idBrainpoolP160r1:
            return { name: ECDSA, namedCurve: brainpoolP160r1 };
          case asn1.idBrainpoolP160t1:
            return { name: ECDSA, namedCurve: brainpoolP160t1 };
          case asn1.idBrainpoolP192r1:
            return { name: ECDSA, namedCurve: brainpoolP192r1 };
          case asn1.idBrainpoolP192t1:
            return { name: ECDSA, namedCurve: brainpoolP192t1 };
          case asn1.idBrainpoolP224r1:
            return { name: ECDSA, namedCurve: brainpoolP224r1 };
          case asn1.idBrainpoolP224t1:
            return { name: ECDSA, namedCurve: brainpoolP224t1 };
          case asn1.idBrainpoolP256r1:
            return { name: ECDSA, namedCurve: brainpoolP256r1 };
          case asn1.idBrainpoolP256t1:
            return { name: ECDSA, namedCurve: brainpoolP256t1 };
          case asn1.idBrainpoolP320r1:
            return { name: ECDSA, namedCurve: brainpoolP320r1 };
          case asn1.idBrainpoolP320t1:
            return { name: ECDSA, namedCurve: brainpoolP320t1 };
          case asn1.idBrainpoolP384r1:
            return { name: ECDSA, namedCurve: brainpoolP384r1 };
          case asn1.idBrainpoolP384t1:
            return { name: ECDSA, namedCurve: brainpoolP384t1 };
          case asn1.idBrainpoolP512r1:
            return { name: ECDSA, namedCurve: brainpoolP512r1 };
          case asn1.idBrainpoolP512t1:
            return { name: ECDSA, namedCurve: brainpoolP512t1 };
        }
      }
    }

    return null;
  }

}

// register EC algorithm provider as a singleton object
container.registerSingleton(diAlgorithm, EcAlgorithm);