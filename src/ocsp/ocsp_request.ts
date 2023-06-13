import * as ocsp from "@peculiar/asn1-ocsp";
import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSourceConverter } from "pvtsutils";
import { container } from "tsyringe";
import { AsnData } from "../asn_data";
import { Extension } from "../extension";
import { AsnEncodedType, PemData } from "../pem_data";
import { HashedAlgorithm, IExtensionable } from "../types";
import { GeneralName } from "../general_name";
import { PublicKey, PublicKeyType } from "../public_key";
import { CertificateID } from "./cert_id";
import { IAsnSignatureFormatter, diAsnSignatureFormatter } from "../asn_signature_formatter";
import { PemConverter } from "../pem_converter";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { ExtensionFactory } from "../extensions/extension_factory";
import { cryptoProvider } from "../provider";

/**
 * Class that represents the ID of the certificate for which the status is being requested
 */
export class Request extends AsnData<ocsp.Request> implements IExtensionable {

  /**
   * The ID of the certificate for which the status is being requested
   */
  public certificateID!: CertificateID;

  public extensions!: Extension[];

  protected onInit(asn: ocsp.Request): void {
    this.certificateID = new CertificateID(asn.reqCert);
    this.extensions = [];
    if (asn.singleRequestExtensions) {
      this.extensions = asn.singleRequestExtensions.map(o => ExtensionFactory.create(AsnConvert.serialize(o)));
    }
  }

  constructor(raw: AsnEncodedType);
  constructor(asn: ocsp.Request);
  public constructor(param: AsnEncodedType | ocsp.Request) {
    if (PemData.isAsnEncoded(param)) {
      super(PemData.toArrayBuffer(param), ocsp.Request);
    } else {
      super(param);
    }
  }

  public getExtension<T extends Extension>(type: new () => T): T | null;
  public getExtension<T extends Extension>(type: string): T | null;
  public getExtension<T extends Extension>(type: { new(): T; } | string): T | null {
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
  public getExtensions<T extends Extension>(type: new () => T): T[];
  public getExtensions<T extends Extension>(type: string): T[];
  public getExtensions<T extends Extension>(type: string | { new(raw: BufferSource): T; }): T[] {
    return this.extensions.filter(o => {
      if (typeof type === "string") {
        return o.type === type;
      } else {
        return o instanceof type;
      }
    }) as T[];
  }
}

/**
 * Class that represents an open certificate status request (OCSP).
 */
export class OCSPRequest extends PemData<ocsp.OCSPRequest> implements IExtensionable {
  protected readonly tag;

  /**
   * ToBeSigned block of OCSP request
   */
  private tbs!: ArrayBuffer;

  /**
   * Gets a signature algorithm
   * If not specified, no signature is required
   */
  public signatureAlgorithm?: HashedAlgorithm;

  /**
   * The signature of the OCSP request
   * If not specified, no signature is required
   * If specified, it must be generated using the private key corresponding to the public key specified in the request
   */
  public signature?: ArrayBuffer;

  /**
   * Gets the identity of the requestor that signed this OCSP request
   */
  public requestor?: GeneralName;

  /**
   * Gets a list of certificate IDs for which the status is being requested
   */
  public requestList!: Request[];

  /**
   * Gets a list of request extensions
   */
  extensions!: Extension[];

  protected onInit(asn: ocsp.OCSPRequest): void {
    const tbs = asn.tbsRequest;
    this.tbs = AsnConvert.serialize(tbs);
    if (tbs.requestorName) this.requestor = new GeneralName(tbs.requestorName);
    if (asn.optionalSignature) {
      this.signature = asn.optionalSignature.signature;
      const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
      this.signatureAlgorithm = algProv.toWebAlgorithm(asn.optionalSignature.signatureAlgorithm) as HashedAlgorithm;
    }
    this.extensions = [];
    if (tbs.requestExtensions) {
      this.extensions = tbs.requestExtensions.map((o) =>
        ExtensionFactory.create(AsnConvert.serialize(o))
      );
    }
    this.requestList = tbs.requestList.map(o => new Request(AsnConvert.serialize(o)));
  }

  constructor(raw: AsnEncodedType);
  constructor(tbsRequest: ocsp.OCSPRequest);
  public constructor(param: AsnEncodedType | ocsp.OCSPRequest) {
    if (PemData.isAsnEncoded(param)) {
      super(param, ocsp.OCSPRequest);
    } else {
      super(param);
    }

    this.tag = PemConverter.OCSPRequestTag;
  }

  public getExtension<T extends Extension>(type: string): T | null;
  public getExtension<T extends Extension>(type: new () => T): T | null;
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
  public getExtensions<T extends Extension>(type: string): T[];
  public getExtensions<T extends Extension>(type: new () => T): T[];
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
   * Validates a OCSP request signature
   * @param signer The public key used to verify the signature of the OCSP request
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns True if the signature is valid. Otherwise false
   *
   * @remarks
   * If the OCSP request is not signed, then the check always returns `true`.
   */
  public async verify(signer: PublicKeyType, crypto = cryptoProvider.get()): Promise<boolean> {
    let keyAlgorithm: Algorithm;

    // Convert public key to CryptoKey
    let publicKey: CryptoKey;
    try {
      if ("publicKey" in signer) {
        // IPublicKeyContainer
        keyAlgorithm = { ...signer.publicKey.algorithm, ...this.signatureAlgorithm };
        publicKey = await signer.publicKey.export(keyAlgorithm, ["verify"], crypto);
      } else if (signer instanceof PublicKey) {
        // PublicKey
        keyAlgorithm = { ...signer.algorithm, ...this.signatureAlgorithm };
        publicKey = await signer.export(keyAlgorithm, ["verify"], crypto);
      } else if (BufferSourceConverter.isBufferSource(signer)) {
        const key = new PublicKey(signer);
        keyAlgorithm = { ...key.algorithm, ...this.signatureAlgorithm };
        publicKey = await key.export(keyAlgorithm, ["verify"], crypto);
      } else {
        // CryptoKey
        keyAlgorithm = { ...signer.algorithm, ...this.signatureAlgorithm };
        publicKey = signer;
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
      if (this.signature) {
        signature = signatureFormatter.toWebSignature(keyAlgorithm, this.signature);
        if (signature) {
          break;
        }
      }
    }
    if (!signature) {
      throw Error("Cannot convert ASN.1 signature value to WebCrypto format");
    }

    if (this.signatureAlgorithm) {
      return await crypto.subtle.verify(this.signatureAlgorithm, publicKey, signature, this.tbs);
    }

    return true;
  }
}