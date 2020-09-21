import { id_rsaEncryption, RSAPublicKey } from "@peculiar/asn1-rsa";
import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { container } from "tsyringe";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { AsnData } from "./asn_data";
import { cryptoProvider } from "./provider";

/**
 * Representation of Subject Public Key Info
 */
export class PublicKey extends AsnData<SubjectPublicKeyInfo>{

  /**
   * Gets a key algorithm
   */
  public algorithm!: Algorithm;

  /**
   * Returns a public CryptoKey
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async export(crypto?: Crypto): Promise<CryptoKey>;
  /**
   * Returns a public CryptoKey with specified parameters
   * @param algorithm Algorithm
   * @param keyUsages A list of key usages
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async export(algorithm: Algorithm | EcKeyImportParams, keyUsages: KeyUsage[], crypto?: Crypto): Promise<CryptoKey>;
  public async export(...args: any[]) {
    let crypto: Crypto;
    let keyUsages: KeyUsage[] = ["verify"];
    let algorithm = { hash: "SHA-256", ...this.algorithm };

    if (args.length > 1) {
      // alg, usages, crypto?
      algorithm = args[0] || algorithm;
      keyUsages = args[1] || keyUsages;
      crypto = args[2] || cryptoProvider.get();
    } else {
      // crypto?
      crypto = args[0] || cryptoProvider.get();
    }

    // create a public key
    return crypto.subtle.importKey("spki", this.rawData, algorithm, true, keyUsages);
  }

  protected onInit(asn: SubjectPublicKeyInfo) {
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    const algorithm = this.algorithm = algProv.toWebAlgorithm(asn.algorithm) as any;
    switch (asn.algorithm.algorithm) {
      case id_rsaEncryption:
        {
          const rsaPublicKey = AsnConvert.parse(asn.subjectPublicKey, RSAPublicKey);
          const modulus = BufferSourceConverter.toUint8Array(rsaPublicKey.modulus);
          algorithm.publicExponent = BufferSourceConverter.toUint8Array(rsaPublicKey.publicExponent);
          algorithm.modulusLength = (!modulus[0] ? modulus.slice(1) : modulus).byteLength << 3;
          break;
        }
    }
  }

  /**
   * Returns a SHA-1 public key thumbprint
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async getThumbprint(crypto?: Crypto): Promise<ArrayBuffer>;
  /**
   * Returns a public key thumbprint for specified mechanism
   * @param algorithm Hash algorithm
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async getThumbprint(algorithm: globalThis.AlgorithmIdentifier, crypto?: Crypto): Promise<ArrayBuffer>;
  public async getThumbprint(...args: any[]) {
    let crypto: Crypto;
    let algorithm = "SHA-1";

    if (args.length === 1 && !args[0]?.subtle) {
      // crypto?
      algorithm = args[0] || algorithm;
      crypto = args[1] || cryptoProvider.get();
    } else {
      crypto = args[0] || cryptoProvider.get();
    }
    return await crypto.subtle.digest(algorithm, this.rawData);
  }

}