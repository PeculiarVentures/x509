import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { container, injectable } from "tsyringe";
import { diAlgorithm, IAlgorithm } from "./algorithm";
import { id_sha1, id_sha256, id_sha384, id_sha512 } from "@peculiar/asn1-rsa";



/**
 * SHA algorithm provider
 */
@injectable()
export class ShaAlgorithm implements IAlgorithm {

  public toAsnAlgorithm(alg: EcKeyGenParams): AlgorithmIdentifier | null {
    let algorithm: string | null = null;
    switch (alg.name.toLowerCase()) {
      case "sha-1":
        algorithm = id_sha1;
        break;
      case "sha-256":
        algorithm = id_sha256;
        break;
      case "sha-384":
        algorithm = id_sha384;
        break;
      case "sha-512":
        algorithm = id_sha512;
        break;
    }
    if (algorithm) {
      return new AlgorithmIdentifier({
        algorithm,
        parameters: null,
      });
    }

    return null;
  }

  public toWebAlgorithm(alg: AlgorithmIdentifier): Algorithm | null {
    switch (alg.algorithm) {
      case id_sha1:
        return { name: "SHA-1" };
      case id_sha256:
        return { name: "SHA-256" };
      case id_sha384:
        return { name: "SHA-384" };
      case id_sha512:
        return { name: "SHA-512" };
    }

    return null;
  }

}

// register SHA algorithm provider as a singleton object
container.registerSingleton(diAlgorithm, ShaAlgorithm);