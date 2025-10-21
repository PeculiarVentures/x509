import { AsnConvert } from "@peculiar/asn1-schema";
import {
  CertificateList, Version, AlgorithmIdentifier,
} from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
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
import { generateCertificateSerialNumber } from "./utils";

export interface X509CrlVerifyParams {
  publicKey: CryptoKey | PublicKey | X509Certificate;
}

/**
 * Representation of X.509 Certificate Revocation List (CRL)
 */
export class X509Crl extends PemData<CertificateList> {
  protected readonly tag = PemConverter.CrlTag;

  /**
   * ToBeSigned block of crl
   */
  #tbs?: ArrayBuffer;

  /**
   * Signature algorithm
   */
  #signatureAlgorithm?: HashedAlgorithm;

  /**
   * Issuer name
   */
  #issuerName?: Name;

  /**
   * This update date
   */
  #thisUpdate?: Date;

  /**
   * Next update date
   */
  #nextUpdate?: Date;

  /**
   * CRL entries
   */
  #entries?: readonly X509CrlEntry[];

  /**
   * CRL extensions
   */
  #extensions?: Extension[];

  /**
   * Gets a version
   */
  public get version(): Version | undefined {
    return this.asn.tbsCertList.version;
  }

  /**
   * Gets a signature algorithm
   */
  public get signatureAlgorithm(): HashedAlgorithm {
    if (!this.#signatureAlgorithm) {
      const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
      this.#signatureAlgorithm = algProv
        .toWebAlgorithm(this.asn.signatureAlgorithm) as HashedAlgorithm;
    }

    return this.#signatureAlgorithm;
  }

  /**
   * Gets a signature
   */
  public get signature(): ArrayBuffer {
    return this.asn.signature;
  }

  /**
   * Gets a string issuer name
   */
  public get issuer(): string {
    return this.issuerName!.toString();
  }

  /**
   * Gets the issuer value from the crl as an Name
   */
  public get issuerName(): Name {
    if (!this.#issuerName) {
      this.#issuerName = new Name(this.asn.tbsCertList.issuer);
    }

    return this.#issuerName;
  }

  /**
   * Gets a thisUpdate date from the CRL
   */
  public get thisUpdate(): Date {
    if (!this.#thisUpdate) {
      const thisUpdate = this.asn.tbsCertList.thisUpdate.getTime();
      if (!thisUpdate) {
        throw new Error("Cannot get 'thisUpdate' value");
      }
      this.#thisUpdate = thisUpdate;
    }

    return this.#thisUpdate;
  }

  /**
   * Gets a nextUpdate date from the CRL
   */
  public get nextUpdate(): Date | undefined {
    if (this.#nextUpdate === undefined) {
      this.#nextUpdate = this.asn.tbsCertList.nextUpdate?.getTime() || undefined;
    }

    return this.#nextUpdate;
  }

  /**
   * Gets a crlEntries from the CRL
   *
   * @remarks
   * Reading this property parses all revoked certificates, which can be slow for large CRLs.
   * Use findRevoked() for efficient searching of specific certificates.
   */
  public get entries(): readonly X509CrlEntry[] {
    if (!this.#entries) {
      this.#entries = this.asn.tbsCertList
        .revokedCertificates?.map((o) => new X509CrlEntry(o)) || [];
    }

    return this.#entries;
  }

  /**
   * Gets a list of crl extensions
   */
  public get extensions(): Extension[] {
    if (!this.#extensions) {
      this.#extensions = [];
      if (this.asn.tbsCertList.crlExtensions) {
        this.#extensions = this.asn.tbsCertList.crlExtensions.map((o) =>
          ExtensionFactory.create(AsnConvert.serialize(o)),
        );
      }
    }

    return this.#extensions;
  }

  /**
   * Gets the ToBeSigned block
   */
  private get tbs(): ArrayBuffer {
    if (!this.#tbs) {
      this.#tbs = this.asn.tbsCertListRaw || AsnConvert.serialize(this.asn.tbsCertList);
    }

    return this.#tbs;
  }

  /**
   * Gets the signature algorithm from tbsCertList
   */
  private get tbsCertListSignatureAlgorithm(): AlgorithmIdentifier {
    return this.asn.tbsCertList.signature;
  }

  /**
   * Gets the signature algorithm from CertificateList
   */
  private get certListSignatureAlgorithm(): AlgorithmIdentifier {
    return this.asn.signatureAlgorithm;
  }

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
    // @ts-expect-error: super call with private fields
    super(param, PemData.isAsnEncoded(param) ? CertificateList : undefined);
  }

  protected onInit(_asn: CertificateList) {
    // Initialization is now lazy
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
  public getExtension<T extends Extension>(type: new(raw: BufferSource) => T): T | null;
  public getExtension<T extends Extension>(
    type: (new(raw: BufferSource) => T) | string,
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
  public getExtensions<T extends Extension>(type: new(raw: BufferSource) => T): T[];
  /**
   * Returns a list of extensions of specified type
   * @param type Extension identifier
   */
  public getExtensions<T extends Extension>(
    type: string | (new(raw: BufferSource) => T),
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
    crypto = cryptoProvider.get(),
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
        keyAlgorithm = {
          ...paramsKey.algorithm, ...this.signatureAlgorithm,
        };
        publicKey = await paramsKey.export(keyAlgorithm, ["verify"]);
      } else {
        // CryptoKey
        keyAlgorithm = {
          ...paramsKey.algorithm, ...this.signatureAlgorithm,
        };
        publicKey = paramsKey;
      }
    } catch {
      // NOTE: Uncomment the next line to see more information about errors
      // console.error(_e);

      // Application will throw exception if public key
      // algorithm is not the same type which is needed
      // for signature validation
      // (eg leaf certificate is signed with RSA mechanism, public key is ECDSA)
      return false;
    }

    // Convert ASN.1 signature to WebCrypto format
    const signatureFormatters = container
      .resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter)
      .reverse();
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
    const serialBuffer = generateCertificateSerialNumber(serialNumber);
    for (const revoked of this.asn.tbsCertList.revokedCertificates || []) {
      if (BufferSourceConverter.isEqual(revoked.userCertificate, serialBuffer)) {
        return new X509CrlEntry(AsnConvert.serialize(revoked));
      }
    }

    return null;
  }
}
