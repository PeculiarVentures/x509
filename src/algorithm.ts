import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { container } from "tsyringe";

export interface UnknownAlgorithm extends Algorithm {
  name: string;
  parameters?: ArrayBuffer | null;
}

export interface IAlgorithm {

  /**
   * Converts WebCrypto algorithm to ASN.1 algorithm
   * @param alg WebCrypto algorithm
   * @returns ASN.1 algorithm or null
   */
  toAsnAlgorithm(alg: Algorithm): AlgorithmIdentifier | null;

  /**
   * Converts ASN.1 algorithm to WebCrypto algorithm
   * @param alg ASN.1 algorithm
   * @returns WebCrypto algorithm or null
   */
  toWebAlgorithm(alg: AlgorithmIdentifier): Algorithm | null;

}

/**
 * Dependency Injection algorithm identifier
 */
export const diAlgorithm = "crypto.algorithm";

export class AlgorithmProvider {
  /**
   * Returns all registered algorithm providers
   */
  public getAlgorithms() {
    return container.resolveAll<IAlgorithm>(diAlgorithm);
  }

  /**
   * Converts WebCrypto algorithm to ASN.1 algorithm
   * @param alg WebCrypto algorithm
   * @returns ASN.1 algorithm
   * @throws Error whenever cannot convert an algorithm
   */
  public toAsnAlgorithm(alg: Algorithm): AlgorithmIdentifier {
    // prepare hashed algorithm
    const algCopy: any = { ...alg };

    if (algCopy.hash && typeof algCopy.hash === "string") {
      algCopy.hash = { name: algCopy.hash };
    }

    for (const algorithm of this.getAlgorithms()) {
      const res = algorithm.toAsnAlgorithm(alg);

      if (res) {
        return res;
      }
    }

    if (/^[0-9.]+$/.test(alg.name)) {
      const res = new AlgorithmIdentifier({ algorithm: alg.name });

      if ("parameters" in alg) {
        const unknown = alg as UnknownAlgorithm;

        res.parameters = unknown.parameters;
      }

      return res;
    }

    throw new Error("Cannot convert WebCrypto algorithm to ASN.1 algorithm");
  }

  /**
   * ConvertsASN.1 algorithm to WebCrypto algorithm
   * @param alg ASN.1 algorithm
   * @returns  algorithm
   */
  public toWebAlgorithm(alg: AlgorithmIdentifier): Algorithm {
    for (const algorithm of this.getAlgorithms()) {
      const res = algorithm.toWebAlgorithm(alg);

      if (res) {
        return res;
      }
    }

    const unknown: UnknownAlgorithm = {
      name: alg.algorithm,
      parameters: alg.parameters,
    };

    return unknown;
  }
}

export const diAlgorithmProvider = "crypto.algorithmProvider";

// register AlgorithmProvider as a singleton object
container.registerSingleton(diAlgorithmProvider, AlgorithmProvider);
