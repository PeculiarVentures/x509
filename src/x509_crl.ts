import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificateList, Version, AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { container } from "tsyringe";
import { HashedAlgorithm } from "./types";
import { cryptoProvider } from "./provider";
import { Name } from "./name";
import { Extension } from "./extension";
import { ExtensionFactory } from "./extensions/extension_factory";
import { PublicKey } from "./public_key";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { AsnEncodedType, PemData } from "./pem_data";
import {
  diAsnSignatureFormatter,
  IAsnSignatureFormatter,
} from "./asn_signature_formatter";
import { X509Certificate } from "./x509_cert";
import { X509CrlEntry } from "./x509_crl_entry";
import { PemConverter } from "./pem_converter";

export interface X509CrlVerifyParams {
  publicKey: CryptoKey | PublicKey | X509Certificate;
}

/**
 * Representation of X.509 Certificate Revocation List (CRL)
 */
export class X509Crl extends PemData<CertificateList> {
  protected readonly tag;

  /**
   * ToBeSigned block of crl
   */
  private tbs!: ArrayBuffer;

  /**
   * Signature field in the sequence tbsCertList
   */
  private tbsCertListSignatureAlgorithm!: AlgorithmIdentifier;

  /**
   * Signature algorithm field in the sequence CertificateList
   */
  private certListSignatureAlgorithm!: AlgorithmIdentifier;

  /**
   * Gets a version
   */
  public version?: Version;

  /**
   * Gets a signature algorithm
   */
  public signatureAlgorithm!: HashedAlgorithm;

  /**
   * Gets a signature
   */
  public signature!: ArrayBuffer;

  /**
   * Gets a string issuer name
   */
  public issuer!: string;

  /**
   * Gets the issuer value from the crl as an Name
   */
  public issuerName!: Name;

  /**
   * Gets a thisUpdate date from the CRL
   */
  public thisUpdate!: Date;

  /**
   * Gets a nextUpdate date from the CRL
   */
  public nextUpdate?: Date;

  /**
   * Gets a crlEntries from the CRL
   */
  public entries!: ReadonlyArray<X509CrlEntry>;

  /**
   * Gts a list of crl extensions
   */
  public extensions!: Extension[];

  /**
   * Creates a new instance from ASN.1 CertificateList object
   * @param asn ASN.1 CertificateList object
   */
  public constructor(asn: CertificateList);
  /**
   * Creates a new instance
   * @param raw Encoded buffer (DER, PEM, HEX, Base64, Base64Url)
   */
  public constructor(raw: AsnEncodedType);
  public constructor(param: AsnEncodedType | CertificateList) {
    if (PemData.isAsnEncoded(param)) {
      super(param, CertificateList);
    } else {
      super(param);
    }

    this.tag = PemConverter.CrlTag;
  }

  protected onInit(asn: CertificateList) {
    const tbs = asn.tbsCertList;
    this.tbs = AsnConvert.serialize(tbs);
    this.version = tbs.version;
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    this.signatureAlgorithm = algProv.toWebAlgorithm(asn.signatureAlgorithm) as HashedAlgorithm;
    this.tbsCertListSignatureAlgorithm = tbs.signature;
    this.certListSignatureAlgorithm = asn.signatureAlgorithm;
    this.signature = asn.signature;
    this.issuerName = new Name(tbs.issuer);
    this.issuer = this.issuerName.toString();
    const thisUpdate = tbs.thisUpdate.getTime();
    if (!thisUpdate) {
      throw new Error("Cannot get 'thisUpdate' value");
    }
    this.thisUpdate = thisUpdate;
    const nextUpdate = tbs.nextUpdate?.getTime();
    this.nextUpdate = nextUpdate;
    this.entries = tbs.revokedCertificates?.map(o => new X509CrlEntry(AsnConvert.serialize(o))) || [];

    this.extensions = [];
    if (tbs.crlExtensions) {
      this.extensions = tbs.crlExtensions.map((o) =>
        ExtensionFactory.create(AsnConvert.serialize(o))
      );
    }
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
  public getExtension<T extends Extension>(type: {
    new(raw: BufferSource): T;
  }): T | null;
  public getExtension<T extends Extension>(
    type: { new(raw: BufferSource): T; } | string
  ): T | null {
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
  public getExtensions<T extends Extension>(type: {
    new(raw: BufferSource): T;
  }): T[];
  /**
   * Returns a list of extensions of specified type
   * @param type Extension identifier
   */
  public getExtensions<T extends Extension>(
    type: string | { new(raw: BufferSource): T; }
  ): T[] {
    return this.extensions.filter((o) => {
      if (typeof type === "string") {
        return o.type === type;
      } else {
        return o instanceof type;
      }
    }) as T[];
  }

  /**
   * Validates a crl signature
   * @param params Verification parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async verify(
    params: X509CrlVerifyParams,
    crypto = cryptoProvider.get()
  ) {
    if (!this.certListSignatureAlgorithm.isEqual(this.tbsCertListSignatureAlgorithm)) {
      throw new Error("algorithm identifier in the sequence tbsCertList and CertificateList mismatch");
    }

    let keyAlgorithm: Algorithm;

    // Convert public key to CryptoKey
    let publicKey: CryptoKey;
    const paramsKey = params.publicKey;
    try {
      if (paramsKey instanceof X509Certificate) {
        // X509Certificate
        keyAlgorithm = {
          ...paramsKey.publicKey.algorithm,
          ...paramsKey.signatureAlgorithm,
        };
        publicKey = await paramsKey.publicKey.export(keyAlgorithm, ["verify"]);
      } else if (paramsKey instanceof PublicKey) {
        // PublicKey
        keyAlgorithm = { ...paramsKey.algorithm, ...this.signature };
        publicKey = await paramsKey.export(keyAlgorithm, ["verify"]);
      } else {
        // CryptoKey
        keyAlgorithm = { ...paramsKey.algorithm, ...this.signature };
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

    return await crypto.subtle.verify(this.signatureAlgorithm, publicKey, signature, this.tbs);
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
  public async getThumbprint(
    algorithm: globalThis.AlgorithmIdentifier,
    crypto?: Crypto
  ): Promise<ArrayBuffer>;
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

  /**
   *  Gets the CRL entry, with the given X509Certificate or certificate serialNumber.
   *
   * @param certOrSerialNumber certificate | serialNumber
   */
  public findRevoked(certOrSerialNumber: X509Certificate | string): X509CrlEntry | null {
    const serialNumber = typeof certOrSerialNumber === "string" ? certOrSerialNumber : certOrSerialNumber.serialNumber;
    for (const entry of this.entries) {
      if (entry.serialNumber === serialNumber) {
        return entry;
      }
    }

    return null;
  }
}
