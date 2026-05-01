import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import {
  id_ml_dsa_44,
  id_ml_dsa_65,
  id_ml_dsa_87,
} from "@peculiar/asn1-x509-post-quantum";
import { container, injectable } from "tsyringe";
import { diAlgorithm, IAlgorithm } from "./algorithm";

/**
 * Provider for the NIST FIPS 204 module-lattice digital signature algorithms
 * (ML-DSA-44 / -65 / -87). Per FIPS 204 §5 and NIST CSOR the AlgorithmIdentifier
 * carries no parameters (absent, not NULL), matching the Ed25519 convention.
 */
@injectable()
export class MlDsaAlgorithm implements IAlgorithm {
  public toAsnAlgorithm(alg: Algorithm): AlgorithmIdentifier | null {
    let algorithm: string | null = null;
    switch (alg.name.toLowerCase()) {
      case "ml-dsa-44":
        algorithm = id_ml_dsa_44;
        break;
      case "ml-dsa-65":
        algorithm = id_ml_dsa_65;
        break;
      case "ml-dsa-87":
        algorithm = id_ml_dsa_87;
        break;
    }
    if (algorithm) {
      return new AlgorithmIdentifier({ algorithm });
    }
    return null;
  }

  public toWebAlgorithm(alg: AlgorithmIdentifier): Algorithm | null {
    switch (alg.algorithm) {
      case id_ml_dsa_44:
        return { name: "ML-DSA-44" };
      case id_ml_dsa_65:
        return { name: "ML-DSA-65" };
      case id_ml_dsa_87:
        return { name: "ML-DSA-87" };
    }
    return null;
  }
}

// register ML-DSA algorithm provider as a singleton object
container.registerSingleton(diAlgorithm, MlDsaAlgorithm);
