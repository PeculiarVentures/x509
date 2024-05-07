import * as ocsp from "@peculiar/asn1-ocsp";
import { AsnConvert } from "@peculiar/asn1-schema";
import { container } from "tsyringe";
import { AsnData } from "../asn_data";
import { ICertificateStorage, ICertificateStorageHandler } from "../certificate_storage_handler";
import { HashedAlgorithm, IExtensionable } from "../types";
import { X509Certificates } from "../x509_certs";
import { Extension } from "../extension";
import { SingleResponse } from "./single_response";
import { AsnEncodedType, PemData } from "../pem_data";
import { X509Certificate } from "../x509_cert";
import { CertificateID } from "./cert_id";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { ExtensionFactory } from "../extensions/extension_factory";
import { DefaultCertificateStorageHandler } from "../default_certificate_storage_handler";
import { cryptoProvider } from "../provider";
import { PublicKey, PublicKeyType } from "../public_key";
import { BufferSourceConverter } from "pvtsutils";
import { IAsnSignatureFormatter, diAsnSignatureFormatter } from "../asn_signature_formatter";


/**
 * A class that represents the basic response to an open certificate status request (OCSP)
 */
export class BasicOCSPResponse extends AsnData<ocsp.BasicOCSPResponse> implements ICertificateStorage, IExtensionable {
  /**
   * ToBeSigned block of BasicOCSPResponse
   */
  private tbs!: ArrayBuffer;

  /**
   * Certificate Storege
   */
  public certificateStorage!: ICertificateStorageHandler; // OCSPCertificateStorage(ocsp: BasicOCSPResponse).parent = appStorage

  /**
   * Returns the certificates included in the response
   */
  public certificates!: X509Certificates;

  /**
   * The hash algorithm identifier for signing the OCSP response
   */
  public signatureAlgorithm!: HashedAlgorithm;

  /**
   * OCSP response signature
   */
  public signature!: ArrayBuffer;

  /**
   * The ID of the responder that signed this OCSP response
   * Can be represented as either a string (byName) or an ArrayBuffer (byKey)
   */
  public responderID?: string | ArrayBuffer; // string - byName, ArrayBuffer - byKey

  /**
   * The date and time the OCSP response was signed
   */
  public producedAt!: Date;

  public responses!: SingleResponse[];

  public extensions!: Extension[];

  protected onInit(asn: ocsp.BasicOCSPResponse): void {
    this.tbs = AsnConvert.serialize(asn.tbsResponseData);
    this.certificates = new X509Certificates();
    if (asn.certs) {
      for (const item of asn.certs) {
        this.certificates.push(new X509Certificate(item));
      }
    }
    this.certificateStorage = new DefaultCertificateStorageHandler();
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    this.signatureAlgorithm = algProv.toWebAlgorithm(asn.signatureAlgorithm) as HashedAlgorithm;
    this.signature = BufferSourceConverter.toArrayBuffer(asn.signature);
    if (asn.tbsResponseData.responderID.byName) {
      this.responderID = asn.tbsResponseData.responderID.byName.toString();
    }
    if (asn.tbsResponseData.responderID.byKey) {
      this.responderID = asn.tbsResponseData.responderID.byKey.buffer;
    }
    this.producedAt = asn.tbsResponseData.producedAt;
    this.responses = [];
    asn.tbsResponseData.responses.map((o) => new SingleResponse(o));
    this.extensions = [];
    if (asn.tbsResponseData.responseExtensions) {
      this.extensions = asn.tbsResponseData.responseExtensions.map((o) =>
        ExtensionFactory.create(AsnConvert.serialize(o))
      );
    }
  }

  constructor(raw: AsnEncodedType);
  constructor(asn: ocsp.BasicOCSPResponse);
  public constructor(param: AsnEncodedType | ocsp.BasicOCSPResponse) {
    if (PemData.isAsnEncoded(param)) {
      super(PemData.toArrayBuffer(param), ocsp.BasicOCSPResponse);
    } else {
      super(param);
    }
  }

  /**
   * Find the responder certificate that was used to sign this OCSP response
   * @returns Responder certificate or null if not found
   */
  public findResponder(): X509Certificate | null {
    if (this.responderID) {

      const cert = typeof this.responderID === "string" ?
        new X509Certificate(PemData.toArrayBuffer(this.responderID))
        : new X509Certificate(this.responderID);

      return cert;
    }

    return null;
  }

  /**
   * Search for the certificate for which the status is being requested
   * @param certID The ID of the certificate for which the status is being requested
   */
  public findSingleResponse(certID: CertificateID): SingleResponse | null {
    for (const response of this.responses) {
      if (response.certificateID.serialNumber === certID.serialNumber) {
        const singleResponse: SingleResponse = new SingleResponse(AsnConvert.serialize(certID));

        return singleResponse;
      }
    }

    return null;
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

  /**
   * Verifies the signature of an OCSP response
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns Signature verification result.
   *
   * @remarks
   * Checks only the mathematical correctness of the signature, does not check the respondent's certificate.
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

    return false;
  }
}