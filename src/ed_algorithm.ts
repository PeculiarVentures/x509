import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { container, injectable } from "tsyringe";
import { diAlgorithm, IAlgorithm } from "./algorithm";
import { HashedAlgorithm } from "./types";

// id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
export const idX25519 = "1.3.101.110";
// id-X448      OBJECT IDENTIFIER ::= { 1 3 101 111 }
export const idX448 = "1.3.101.111";
// id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
export const idEd25519 = "1.3.101.112";
// id-Ed448     OBJECT IDENTIFIER ::= { 1 3 101 113 }
export const idEd448 = "1.3.101.113";

/**
 * ECDH-ES and EdDSA algorithm provider
 */
@injectable()
export class EdAlgorithm implements IAlgorithm {

  public toAsnAlgorithm(alg: EcKeyGenParams): AlgorithmIdentifier | null {
    let algorithm: string | null = null;
    switch (alg.name.toLowerCase()) {
      case "eddsa":
        switch (alg.namedCurve.toLowerCase()) {
          case "ed25519":
            algorithm = idEd25519;
            break;
          case "ed448":
            algorithm = idEd448;
            break;
        }
        break;
      case "ecdh-es":
        switch (alg.namedCurve.toLowerCase()) {
          case "x25519":
            algorithm = idX25519;
            break;
          case "x448":
            algorithm = idX448;
            break;
        }
    }
    if (algorithm) {
      return new AlgorithmIdentifier({
        algorithm,
      });
    }

    return null;
  }

  public toWebAlgorithm(alg: AlgorithmIdentifier): HashedAlgorithm | EcKeyGenParams | null {
    switch (alg.algorithm) {
      case idEd25519:
        return { name: "EdDSA", namedCurve: "Ed25519" };
      case idEd448:
        return { name: "EdDSA", namedCurve: "Ed448" };
      case idX25519:
        return { name: "ECDH-ES", namedCurve: "X25519" };
      case idX448:
        return { name: "ECDH-ES", namedCurve: "X448" };
    }

    return null;
  }

}

// register ED algorithm provider as a singleton object
container.registerSingleton(diAlgorithm, EdAlgorithm);