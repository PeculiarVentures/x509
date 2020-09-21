import * as asn1Rsa from "@peculiar/asn1-rsa";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { container, injectable } from "tsyringe";
import { diAlgorithm, IAlgorithm } from "./algorithm";
import { HashedAlgorithm } from "./types";

/**
 * RSA algorithm provider
 */
@injectable()
export class RsaAlgorithm implements IAlgorithm {

  public toAsnAlgorithm(alg: HashedAlgorithm): AlgorithmIdentifier | null {
    switch (alg.name.toLowerCase()) {
      case "rsassa-pkcs1-v1_5":
        if (alg.hash) {
          switch (alg.hash.name.toLowerCase()) {
            case "sha-1":
              return new AlgorithmIdentifier({ algorithm: asn1Rsa.id_sha1WithRSAEncryption, parameters: null });
            case "sha-256":
              return new AlgorithmIdentifier({ algorithm: asn1Rsa.id_sha256WithRSAEncryption, parameters: null });
            case "sha-384":
              return new AlgorithmIdentifier({ algorithm: asn1Rsa.id_sha384WithRSAEncryption, parameters: null });
            case "sha-512":
              return new AlgorithmIdentifier({ algorithm: asn1Rsa.id_sha512WithRSAEncryption, parameters: null });
          }
        } else {
          return new AlgorithmIdentifier({ algorithm: asn1Rsa.id_rsaEncryption, parameters: null });
        }
    }
    return null;
  }

  public toWebAlgorithm(alg: AlgorithmIdentifier): Algorithm | HashedAlgorithm | null {
    switch (alg.algorithm) {
      case asn1Rsa.id_rsaEncryption:
        return { name: "RSASSA-PKCS1-v1_5" };
      case asn1Rsa.id_sha1WithRSAEncryption:
        return { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-1" } };
      case asn1Rsa.id_sha256WithRSAEncryption:
        return { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } };
      case asn1Rsa.id_sha384WithRSAEncryption:
        return { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-384" } };
      case asn1Rsa.id_sha512WithRSAEncryption:
        return { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-512" } };
    }
    return null;
  }

}

// register RSA algorithm provider as a singleton object
container.registerSingleton(diAlgorithm, RsaAlgorithm);