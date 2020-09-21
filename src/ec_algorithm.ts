import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import * as asn1Ecc from "@peculiar/asn1-ecc";
import { container, injectable } from "tsyringe";
import { diAlgorithm, IAlgorithm } from "./algorithm";
import { HashedAlgorithm } from "./types";
import { AsnConvert } from "@peculiar/asn1-schema";

/**
 * EC algorithm provider
 */
@injectable()
export class EcAlgorithm implements IAlgorithm {

  public toAsnAlgorithm(alg: HashedAlgorithm | EcKeyGenParams): AlgorithmIdentifier | null {
    switch (alg.name.toLowerCase()) {
      case "ecdsa":
        if ("hash" in alg) {
          switch (alg.hash.name.toLowerCase()) {
            case "sha-1":
              return new AlgorithmIdentifier({ algorithm: asn1Ecc.id_ecdsaWithSHA1, parameters: null });
            case "sha-256":
              return new AlgorithmIdentifier({ algorithm: asn1Ecc.id_ecdsaWithSHA256, parameters: null });
            case "sha-384":
              return new AlgorithmIdentifier({ algorithm: asn1Ecc.id_ecdsaWithSHA384, parameters: null });
            case "sha-512":
              return new AlgorithmIdentifier({ algorithm: asn1Ecc.id_ecdsaWithSHA512, parameters: null });
          }
        } else if ("namedCurve" in alg) {
          let parameters = "";
          switch (alg.namedCurve) {
            case "P-256":
              parameters = asn1Ecc.id_secp256r1;
              break;
            case "P-384":
              parameters = asn1Ecc.id_secp384r1;
              break;
            case "P-521":
              parameters = asn1Ecc.id_secp521r1;
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
        return { name: "ECDSA", hash: { name: "SHA-1" } };
      case asn1Ecc.id_ecdsaWithSHA256:
        return { name: "ECDSA", hash: { name: "SHA-256" } };
      case asn1Ecc.id_ecdsaWithSHA384:
        return { name: "ECDSA", hash: { name: "SHA-384" } };
      case asn1Ecc.id_ecdsaWithSHA512:
        return { name: "ECDSA", hash: { name: "SHA-512" } };
      case asn1Ecc.id_ecPublicKey: {
        const parameters = AsnConvert.parse(alg.parameters!, asn1Ecc.ECParameters);
        switch (parameters.namedCurve) {
          case asn1Ecc.id_secp256r1:
            return { name: "ECDSA", namedCurve: "P-256" };
          case asn1Ecc.id_secp384r1:
            return { name: "ECDSA", namedCurve: "P-384" };
          case asn1Ecc.id_secp521r1:
            return { name: "ECDSA", namedCurve: "P-521" };
        }
      }
    }
    return null;
  }

}

// register EC algorithm provider as a singleton object
container.registerSingleton(diAlgorithm, EcAlgorithm);