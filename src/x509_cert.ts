import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { HashedAlgorithm } from "./types";
import { cryptoProvider } from "./provider";
import { Name } from "./name";
import { Extension } from "./extension";
import { AsnData } from "./asn_data";
import { ExtensionFactory } from "./extensions";
import { PublicKey } from "./public_key";
import { container } from "tsyringe";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";

/**
 * Verification params of X509 certificate
 */
export interface X509CertificateVerifyParams {
  date?: Date;
  publicKey?: CryptoKey;
  signatureOnly?: boolean;
}

/**
 * Representation of X509 certificate
 */
export class X509Certificate extends AsnData<Certificate> {

  /**
   * ToBeSigned block of certificate
   */
  private tbs!: ArrayBuffer;

  /**
   * Gets a hexadecimal string of the serial number
   */
  public serialNumber!: string;

  /**
   * Gets a string subject name
   */
  public subject!: string;

  /**
   * Gets a string issuer name
   */
  public issuer!: string;

  /**
   * Gets a date before which certificate can't be used
   */
  public notBefore!: Date;

  /**
   * Gets a date after which certificate can't be used
   */
  public notAfter!: Date;

  /**
   * Gets a signature algorithm
   */
  public signatureAlgorithm!: HashedAlgorithm;

  /**
   * Gets a signature
   */
  public signature!: ArrayBuffer;

  /**
   * Gts a list of certificate extensions
   */
  public extensions!: Extension[];

  /**
   * Gets a private key of the certificate
   */
  public privateKey?: CryptoKey;

  /**
   * Gets a public key of the certificate
   */
  public publicKey!: PublicKey;

  /**
   * Creates a new instance from ASN.1 Certificate object
   * @param asn ASN.1 Certificate object
   */
  public constructor(asn: Certificate);
  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  public constructor(param: BufferSource | Certificate) {
    if (BufferSourceConverter.isBufferSource(param)) {
      super(param, Certificate);
    } else {
      super(param);
    }
  }

  protected onInit(asn: Certificate) {
    const tbs = asn.tbsCertificate;
    this.tbs = AsnConvert.serialize(tbs);
    this.serialNumber = Convert.ToHex(tbs.serialNumber);
    this.subject = new Name(tbs.subject).toString();
    this.issuer = new Name(tbs.issuer).toString();
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    this.signatureAlgorithm = algProv.toWebAlgorithm(asn.signatureAlgorithm) as HashedAlgorithm;
    this.signature = asn.signatureValue;
    const notBefore = tbs.validity.notBefore.utcTime || tbs.validity.notBefore.generalTime;
    if (!notBefore) {
      throw new Error("Cannot get 'notBefore' value");
    }
    this.notBefore = notBefore;
    const notAfter = tbs.validity.notAfter.utcTime || tbs.validity.notAfter.generalTime;
    if (!notAfter) {
      throw new Error("Cannot get 'notAfter' value");
    }
    this.notAfter = notAfter;
    this.extensions = [];
    if (tbs.extensions) {
      this.extensions = tbs.extensions.map(o => ExtensionFactory.create(AsnConvert.serialize(o)));
    }
    this.publicKey = new PublicKey(tbs.subjectPublicKeyInfo);
  }

  /**
   * Returns an extension of specified type
   * @param type Extension identifier
   * @returns Extension or null
   */
  public getExtension<T extends Extension>(type: string): T | null {
    for (const ext of this.extensions) {
      if (ext.type === type) {
        return ext as T;
      }
    }
    return null;
  }

  /**
   * Returns a list of extensions of specified type
   * @param type Extension identifier
   */
  public getExtensions<T extends Extension>(type: string): T[] {
    return this.extensions.filter(o => o.type === type) as T[];
  }

  /**
   * Validates a certificate signature
   * @param params Verification parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async verify(params: X509CertificateVerifyParams, crypto = cryptoProvider.get()) {
    const date = params.date || new Date();
    const keyAlgorithm = { ...this.publicKey.algorithm, ...this.signatureAlgorithm };
    const publicKey = params.publicKey || await this.publicKey.export(keyAlgorithm, ["verify"], crypto);

    const ok = await crypto.subtle.verify(this.signatureAlgorithm, publicKey, this.signature, this.tbs);
    if (params.signatureOnly) {
      return ok;
    } else {
      const time = date.getTime();
      return ok && this.notBefore.getTime() < time && time < this.notAfter.getTime();
    }
  }

  /**
   * Returns a SHA-1 certificate thumbprint
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async getThumbprint(crypto?: Crypto): Promise<ArrayBuffer>;
  /**
   * Returns a certificate thumbprint for specified mechanism
   * @param algorithm Hash algorithm
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async getThumbprint(algorithm: globalThis.AlgorithmIdentifier, crypto?: Crypto): Promise<ArrayBuffer>;
  public async getThumbprint(...args: any[]) {
    let crypto = cryptoProvider.get();
    let algorithm = "SHA-1";
    if (args.length === 1 && !args[0]?.subtle) {
      // crypto?
      algorithm = args[0] || algorithm;
      crypto = args[1] || crypto;
    } else {
      crypto = args[0] || crypto;
    }
    return await crypto.subtle.digest(algorithm, this.rawData);
  }

  public async isSelfSigned() {
    return this.subject === this.issuer && await this.verify({ signatureOnly: true });
  }
}