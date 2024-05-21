import * as asn1Rsa from "@peculiar/asn1-rsa";
import { AsnConvert } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { container, injectable } from "tsyringe";
import { AlgorithmProvider, diAlgorithm, diAlgorithmProvider, IAlgorithm } from "./algorithm";
import { HashedAlgorithm } from "./types";

/**
 * RSA algorithm provider
 */
@injectable()
export class RsaAlgorithm implements IAlgorithm {

  public static createPssParams(hash: unknown, saltLength: number): asn1Rsa.RsaSaPssParams | null {
    const hashAlgorithm = RsaAlgorithm.getHashAlgorithm(hash);
    if (!hashAlgorithm) {
      return null;
    }

    return new asn1Rsa.RsaSaPssParams({
      hashAlgorithm,
      maskGenAlgorithm: new AlgorithmIdentifier({
        algorithm: asn1Rsa.id_mgf1,
        parameters: AsnConvert.serialize(hashAlgorithm),
      }),
      saltLength,
    });
  }

  public static getHashAlgorithm(alg: unknown): AlgorithmIdentifier | null {
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    if (typeof alg === "string") {
      return algProv.toAsnAlgorithm({ name: alg });
    } if (typeof alg === "object" && alg && "name" in alg) {
      return algProv.toAsnAlgorithm(alg as Algorithm);
    }

    return null;
  }

  public toAsnAlgorithm(alg: Algorithm): AlgorithmIdentifier | null {
    switch (alg.name.toLowerCase()) {
      case "rsassa-pkcs1-v1_5":
        if ("hash" in alg) {
          let hash: string;
          if (typeof alg.hash === "string") {
            hash = alg.hash;
          } else if (alg.hash && typeof alg.hash === "object"
            && "name" in alg.hash && typeof alg.hash.name === "string") {
            hash = alg.hash.name.toUpperCase();
          } else {
            throw new Error("Cannot get hash algorithm name");
          }

          switch (hash.toLowerCase()) {
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
        break;
      case "rsa-pss":
        if ("hash" in alg) {
          if (!("saltLength" in alg && typeof alg.saltLength === "number")) {
            throw new Error("Cannot get 'saltLength' from 'alg' argument");
          }
          const pssParams = RsaAlgorithm.createPssParams(alg.hash, alg.saltLength);
          if (!pssParams) {
            throw new Error("Cannot create PSS parameters");
          }

          return new AlgorithmIdentifier({ algorithm: asn1Rsa.id_RSASSA_PSS, parameters: AsnConvert.serialize(pssParams) });
        } else {
          return new AlgorithmIdentifier({ algorithm: asn1Rsa.id_RSASSA_PSS, parameters: null });
        }
        break;
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
      case asn1Rsa.id_RSASSA_PSS:
        if (alg.parameters) {
          const pssParams = AsnConvert.parse(alg.parameters, asn1Rsa.RsaSaPssParams);
          const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
          const hashAlg = algProv.toWebAlgorithm(pssParams.hashAlgorithm);

          return {
            name: "RSA-PSS",
            hash: hashAlg,
            saltLength: pssParams.saltLength,
          } as Algorithm;
        } else {
          return { name: "RSA-PSS" };
        }
    }

    return null;
  }

}

// register RSA algorithm provider as a singleton object
container.registerSingleton(diAlgorithm, RsaAlgorithm);