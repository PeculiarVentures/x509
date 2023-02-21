import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate, Version } from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { container } from "tsyringe";
import { HashedAlgorithm } from "./types";
import { cryptoProvider } from "./provider";
import { Name } from "./name";
import { Extension } from "./extension";
import { ExtensionFactory } from "./extensions/extension_factory";
import { IPublicKeyContainer, PublicKey, PublicKeyType } from "./public_key";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { AsnEncodedType, PemData } from "./pem_data";
import { diAsnSignatureFormatter, IAsnSignatureFormatter } from "./asn_signature_formatter";
import { PemConverter } from "./pem_converter";
import { TextConverter, TextObject } from "./text_converter";

/**
 * Verification params of X509 certificate
 */
export interface X509CertificateVerifyParams {
  date?: Date;
  publicKey?: PublicKeyType;
  signatureOnly?: boolean;
}

/**
 * Representation of X509 certificate
 */
export class X509Certificate extends PemData<Certificate> implements IPublicKeyContainer {

  public static override NAME = "Certificate";

  protected readonly tag;

  /**
   * ToBeSigned block of certificate
   */
  private tbs!: ArrayBuffer;

  /**
   * Gets a hexadecimal string of the serial number
   */
  public serialNumber!: string;

  /**
   * Gets the subject value from the certificate as an Name
   */
  public subjectName!: Name;

  /**
   * Gets a string subject name
   */
  public subject!: string;

  /**
   * Gets the issuer value from the certificate as an Name
   */
  public issuerName!: Name;

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
   * Creates a new instance
   * @param raw Encoded buffer (DER, PEM, HEX, Base64, Base64Url)
   */
  public constructor(raw: AsnEncodedType);
  public constructor(param: AsnEncodedType | Certificate) {
    if (PemData.isAsnEncoded(param)) {
      super(param, Certificate);
    } else {
      super(param);
    }

    this.tag = PemConverter.CertificateTag;
  }

  protected onInit(asn: Certificate) {
    const tbs = asn.tbsCertificate;
    this.tbs = AsnConvert.serialize(tbs);
    this.serialNumber = Convert.ToHex(tbs.serialNumber);
    this.subjectName = new Name(tbs.subject);
    this.subject = new Name(tbs.subject).toString();
    this.issuerName = new Name(tbs.issuer);
    this.issuer = this.issuerName.toString();
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
  public getExtension<T extends Extension>(type: string): T | null;
  /**
   * Returns an extension of specified type
   * @param type Extension type
   * @returns Extension or null
   */
  public getExtension<T extends Extension>(type: { new(raw: BufferSource): T; }): T | null;
  public getExtension<T extends Extension>(type: { new(raw: BufferSource): T; } | string): T | null {
    for (const ext of this.extensions) {
      if (typeof type === "string") {
        if (ext.type === type) {
          return ext as T;
        }
      } else {
        if (ext instanceof type) {
          return ext;
        }
      }
    }

    return null;
  }

  /**
   * Returns a list of extensions of specified type
   * @param type Extension identifier
   */
  public getExtensions<T extends Extension>(type: string): T[];
  /**
   * Returns a list of extensions of specified type
   * @param type Extension type
   */
  public getExtensions<T extends Extension>(type: { new(raw: BufferSource): T; }): T[];
  /**
   * Returns a list of extensions of specified type
   * @param type Extension identifier
   */
  public getExtensions<T extends Extension>(type: string | { new(raw: BufferSource): T; }): T[] {
    return this.extensions.filter(o => {
      if (typeof type === "string") {
        return o.type === type;
      } else {
        return o instanceof type;
      }
    }) as T[];
  }

  /**
   * Validates a certificate signature
   * @param params Verification parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async verify(params: X509CertificateVerifyParams = {}, crypto = cryptoProvider.get()) {
    let keyAlgorithm: Algorithm;

    // Convert public key to CryptoKey
    let publicKey: CryptoKey;
    const paramsKey = params.publicKey;
    try {
      if (!paramsKey) {
        // self-signed
        keyAlgorithm = { ...this.publicKey.algorithm, ...this.signatureAlgorithm };
        publicKey = await this.publicKey.export(keyAlgorithm, ["verify"], crypto);
      } else if ("publicKey" in paramsKey) {
        // IPublicKeyContainer
        keyAlgorithm = { ...paramsKey.publicKey.algorithm, ...this.signatureAlgorithm };
        publicKey = await paramsKey.publicKey.export(keyAlgorithm, ["verify"], crypto);
      } else if (paramsKey instanceof PublicKey) {
        // PublicKey
        keyAlgorithm = { ...paramsKey.algorithm, ...this.signatureAlgorithm };
        publicKey = await paramsKey.export(keyAlgorithm, ["verify"], crypto);
      } else if (BufferSourceConverter.isBufferSource(paramsKey)) {
        const key = new PublicKey(paramsKey);
        keyAlgorithm = { ...key.algorithm, ...this.signatureAlgorithm };
        publicKey = await key.export(keyAlgorithm, ["verify"], crypto);
      } else {
        // CryptoKey
        keyAlgorithm = { ...paramsKey.algorithm, ...this.signatureAlgorithm };
        publicKey = paramsKey;
      }
    } catch (e) {
      // NOTE: Uncomment the next line to see more information about errors
      // console.error(e);

      // Application will throw exception if public key algorithm is not the same type which is needed for
      // signature validation (eg leaf certificate is signed with RSA mechanism, public key is ECDSA)
      return false;
    }

    // Convert ASN.1 signature to WebCrypto format
    const signatureFormatters = container.resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter).reverse();
    let signature: ArrayBuffer | null = null;
    for (const signatureFormatter of signatureFormatters) {
      signature = signatureFormatter.toWebSignature(keyAlgorithm, this.signature);
      if (signature) {
        break;
      }
    }
    if (!signature) {
      throw Error("Cannot convert ASN.1 signature value to WebCrypto format");
    }

    const ok = await crypto.subtle.verify(this.signatureAlgorithm, publicKey, signature, this.tbs);
    if (params.signatureOnly) {
      return ok;
    } else {
      const date = params.date || new Date();
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
    let crypto: Crypto;
    let algorithm = "SHA-1";
    if (args[0]) {
      if (!args[0].subtle) {
        // crypto?
        algorithm = args[0] || algorithm;
        crypto = args[1];
      } else {
        crypto = args[0];
      }
    }
    crypto ??= cryptoProvider.get();

    return await crypto.subtle.digest(algorithm, this.rawData);
  }

  public async isSelfSigned(crypto = cryptoProvider.get()): Promise<boolean> {
    return this.subject === this.issuer && await this.verify({ signatureOnly: true }, crypto);
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectEmpty();

    const cert = AsnConvert.parse(this.rawData, Certificate);

    const tbs = cert.tbsCertificate;
    const data = new TextObject("", {
      "Version": `${Version[tbs.version]} (${tbs.version})`,
      "Serial Number": tbs.serialNumber,
      "Signature Algorithm": TextConverter.serializeAlgorithm(tbs.signature),
      "Issuer": this.issuer,
      "Validity": new TextObject("", {
        "Not Before": tbs.validity.notBefore.getTime(),
        "Not After": tbs.validity.notAfter.getTime(),
      }),
      "Subject": this.subject,
      "Subject Public Key Info": this.publicKey,
    });
    if (tbs.issuerUniqueID) {
      data["Issuer Unique ID"] = tbs.issuerUniqueID;
    }
    if (tbs.subjectUniqueID) {
      data["Subject Unique ID"] = tbs.subjectUniqueID;
    }
    if (this.extensions.length) {
      const extensions = new TextObject("");
      for (const ext of this.extensions) {
        const extObj = ext.toTextObject();
        extensions[extObj[TextObject.NAME]] = extObj;
      }
      data["Extensions"] = extensions;
    }
    obj["Data"] = data;

    obj["Signature"] = new TextObject("", {
      "Algorithm": TextConverter.serializeAlgorithm(cert.signatureAlgorithm),
      "": cert.signatureValue,
    });

    return obj;
  }

}
