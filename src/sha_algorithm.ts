import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { container, injectable, diAlgorithm } from "./container";
import { id_sha1, id_sha256, id_sha384, id_sha512 } from "@peculiar/asn1-rsa";
import { IAlgorithm } from "./algorithm";

/**
 * SHA algorithm provider
 */
@injectable()
export class ShaAlgorithm implements IAlgorithm {
  public toAsnAlgorithm(alg: Algorithm): AlgorithmIdentifier | null {
    switch (alg.name.toLowerCase()) {
      case "sha-1":
        return new AlgorithmIdentifier({ algorithm: id_sha1 });
      case "sha-256":
        return new AlgorithmIdentifier({ algorithm: id_sha256 });
      case "sha-384":
        return new AlgorithmIdentifier({ algorithm: id_sha384 });
      case "sha-512":
        return new AlgorithmIdentifier({ algorithm: id_sha512 });
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
