import { AsnConvert } from "@peculiar/asn1-schema";
import { RevokedCertificate, TBSCertList, Version } from "@peculiar/asn1-x509";
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

export interface X509CrlVerifyParams {
  publicKey?: CryptoKey | PublicKey | X509Certificate;
  algorithm?: Algorithm;
}

/**
 * Representation of X.509 Certificate Revocation List (CRL)
 */
export class X509Crl extends PemData<TBSCertList> {
  protected readonly tag;

  /**
   * ToBeSigned block of crl
   */
  private tbs!: ArrayBuffer;

  /**
   * Gets a version
   */
  public version?: Version;

  /**
   * Gets a signature algorithm
   */
  public signature!: HashedAlgorithm;

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
   * Gets a revokedCertificates from the CRL
   */
   public revokedCertificates!: RevokedCertificate[];

  /**
   * Gts a list of crl extensions
   */
  public extensions!: Extension[];

  /**
   * Creates a new instance from ASN.1 TBSCertList object
   * @param asn ASN.1 TBSCertList object
   */
  public constructor(asn: TBSCertList);
  /**
   * Creates a new instance
   * @param raw Encoded buffer (DER, PEM, HEX, Base64, Base64Url)
   */
  public constructor(raw: AsnEncodedType);
  public constructor(param: AsnEncodedType | TBSCertList) {
    if (PemData.isAsnEncoded(param)) {
      super(param, TBSCertList);
    } else {
      super(param);
    }

    this.tag = "CRL";
  }

  protected onInit(asn: TBSCertList) {
    this.version = asn.version;
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    this.signature = algProv.toWebAlgorithm(asn.signature) as HashedAlgorithm;
    this.issuerName = new Name(asn.issuer);
    this.issuer = this.issuerName.toString();
    const thisUpdate = asn.thisUpdate.utcTime || asn.thisUpdate.generalTime;
    if (!thisUpdate) {
      throw new Error("Cannot get 'thisUpdate' value");
    }
    this.thisUpdate = thisUpdate;
    const nextUpdate = asn.nextUpdate?.utcTime || asn.nextUpdate?.generalTime;
    this.nextUpdate = nextUpdate;
    this.revokedCertificates = asn.revokedCertificates || [];

    this.extensions = [];
    if (asn.crlExtensions) {
      this.extensions = asn.crlExtensions.map((o) =>
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
    params: X509CrlVerifyParams = {},
    crypto = cryptoProvider.get()
  ) {
    let keyAlgorithm: Algorithm;

    // Convert public key to CryptoKey
    let publicKey: CryptoKey;
    const paramsKey = params.publicKey;
    try {
      if (!paramsKey) {
        throw new Error("Cannot get publicKey for verify sign");
      } else if (paramsKey instanceof X509Certificate) {
        // X509Certificate
        keyAlgorithm = {
          ...paramsKey.publicKey.algorithm,
          ...this.signature,
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
}
