import { id_ecPublicKey } from "@peculiar/asn1-ecc";
import { id_rsaEncryption, RSAPublicKey } from "@peculiar/asn1-rsa";
import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import { BufferSource, BufferSourceConverter } from "pvtsutils";
import { container } from "tsyringe";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { PemConverter } from "./pem_converter";
import { AsnEncodedType, PemData } from "./pem_data";
import { cryptoProvider } from "./provider";
import { TextConverter, TextObject } from "./text_converter";

export interface IPublicKeyContainer {
  publicKey: PublicKey;
}

export type PublicKeyType = PublicKey | CryptoKey | IPublicKeyContainer | BufferSource;

/**
 * Representation of Subject Public Key Info
 */
export class PublicKey extends PemData<SubjectPublicKeyInfo>{

  protected readonly tag: string;

  /**
   * Gets a key algorithm
   */
  public algorithm!: Algorithm;

  /**
   * Creates a new instance from ASN.1
   * @param asn ASN.1 object
   */
  public constructor(asn: SubjectPublicKeyInfo);
  /**
   * Creates a new instance
   * @param raw Encoded buffer (DER, PEM, HEX, Base64, Base64Url)
   */
  public constructor(raw: AsnEncodedType);
  public constructor(param: AsnEncodedType | SubjectPublicKeyInfo) {
    if (PemData.isAsnEncoded(param)) {
      super(param, SubjectPublicKeyInfo);
    } else {
      super(param);
    }

    this.tag = PemConverter.PublicKeyTag;
  }

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
  public async export(algorithm: Algorithm | EcKeyImportParams | RsaHashedImportParams, keyUsages: KeyUsage[], crypto?: Crypto): Promise<CryptoKey>;
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

    if (args.length >= 1 && !args[0]?.subtle) {
      // crypto?
      algorithm = args[0] || algorithm;
      crypto = args[1] || cryptoProvider.get();
    } else {
      crypto = args[0] || cryptoProvider.get();
    }

    return await crypto.subtle.digest(algorithm, this.rawData);
  }

  /**
   * Returns Subject Key Identifier as specified in {@link https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2 RFC5280}
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async getKeyIdentifier(crypto?: Crypto) {
    if (!crypto) {
      crypto = cryptoProvider.get();
    }

    // The keyIdentifier is composed of the 160-bit SHA-1 hash of the
    // value of the BIT STRING subjectPublicKey (excluding the tag,
    // length, and number of unused bits).

    const asn = AsnConvert.parse(this.rawData, SubjectPublicKeyInfo);

    return await crypto.subtle.digest("SHA-1", asn.subjectPublicKey);
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectEmpty();

    const asn = AsnConvert.parse(this.rawData, SubjectPublicKeyInfo);

    obj["Algorithm"] = TextConverter.serializeAlgorithm(asn.algorithm);

    switch (asn.algorithm.algorithm) {
      case id_ecPublicKey:
        obj["EC Point"] = asn.subjectPublicKey;
        break;
      case id_rsaEncryption:
      default:
        obj["Raw Data"] = asn.subjectPublicKey;
    }

    return obj;
  }

}