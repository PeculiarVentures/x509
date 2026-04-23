import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import {
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
import { container, injectable } from "tsyringe";
import { diAlgorithm, IAlgorithm } from "./algorithm";

/**
 * Provider for the NIST FIPS 205 stateless hash-based digital signature
 * algorithms (SLH-DSA). All 12 parameter sets per FIPS 205 §9. Per FIPS 205
 * and NIST CSOR the AlgorithmIdentifier carries no parameters (absent, not
 * NULL), matching the Ed25519 convention.
 */
@injectable()
export class SlhDsaAlgorithm implements IAlgorithm {
  public toAsnAlgorithm(alg: Algorithm): AlgorithmIdentifier | null {
    let algorithm: string | null = null;
    switch (alg.name.toLowerCase()) {
      case "slh-dsa-sha2-128s":
        algorithm = id_slh_dsa_sha2_128s;
        break;
      case "slh-dsa-sha2-128f":
        algorithm = id_slh_dsa_sha2_128f;
        break;
      case "slh-dsa-sha2-192s":
        algorithm = id_slh_dsa_sha2_192s;
        break;
      case "slh-dsa-sha2-192f":
        algorithm = id_slh_dsa_sha2_192f;
        break;
      case "slh-dsa-sha2-256s":
        algorithm = id_slh_dsa_sha2_256s;
        break;
      case "slh-dsa-sha2-256f":
        algorithm = id_slh_dsa_sha2_256f;
        break;
      case "slh-dsa-shake-128s":
        algorithm = id_slh_dsa_shake_128s;
        break;
      case "slh-dsa-shake-128f":
        algorithm = id_slh_dsa_shake_128f;
        break;
      case "slh-dsa-shake-192s":
        algorithm = id_slh_dsa_shake_192s;
        break;
      case "slh-dsa-shake-192f":
        algorithm = id_slh_dsa_shake_192f;
        break;
      case "slh-dsa-shake-256s":
        algorithm = id_slh_dsa_shake_256s;
        break;
      case "slh-dsa-shake-256f":
        algorithm = id_slh_dsa_shake_256f;
        break;
    }
    if (algorithm) {
      return new AlgorithmIdentifier({ algorithm });
    }
    return null;
  }

  public toWebAlgorithm(alg: AlgorithmIdentifier): Algorithm | null {
    switch (alg.algorithm) {
      case id_slh_dsa_sha2_128s:
        return { name: "SLH-DSA-SHA2-128s" };
      case id_slh_dsa_sha2_128f:
        return { name: "SLH-DSA-SHA2-128f" };
      case id_slh_dsa_sha2_192s:
        return { name: "SLH-DSA-SHA2-192s" };
      case id_slh_dsa_sha2_192f:
        return { name: "SLH-DSA-SHA2-192f" };
      case id_slh_dsa_sha2_256s:
        return { name: "SLH-DSA-SHA2-256s" };
      case id_slh_dsa_sha2_256f:
        return { name: "SLH-DSA-SHA2-256f" };
      case id_slh_dsa_shake_128s:
        return { name: "SLH-DSA-SHAKE-128s" };
      case id_slh_dsa_shake_128f:
        return { name: "SLH-DSA-SHAKE-128f" };
      case id_slh_dsa_shake_192s:
        return { name: "SLH-DSA-SHAKE-192s" };
      case id_slh_dsa_shake_192f:
        return { name: "SLH-DSA-SHAKE-192f" };
      case id_slh_dsa_shake_256s:
        return { name: "SLH-DSA-SHAKE-256s" };
      case id_slh_dsa_shake_256f:
        return { name: "SLH-DSA-SHAKE-256f" };
    }
    return null;
  }
}

// register SLH-DSA algorithm provider as a singleton object
container.registerSingleton(diAlgorithm, SlhDsaAlgorithm);
