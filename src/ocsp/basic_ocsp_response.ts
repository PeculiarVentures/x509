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
import { PublicKey } from "../public_key";
function arrayBufferToHex(buffer: ArrayBuffer): string {
  const byteArray = new Uint8Array(buffer);
  let hexParts = [];
  for (let i = 0; i < byteArray.length; i++) {
    let hex = byteArray[i].toString(16);
    let paddedHex = ('00' + hex).slice(-2);
    hexParts.push(paddedHex);
  }
  return hexParts.join('');
}
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
    this.signature = asn.signature;
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
  public async verify(crypto = cryptoProvider.get()): Promise<boolean> {
    const publicKey = await new PublicKey(this.tbs).export(crypto);

    return await crypto.subtle.verify(this.signatureAlgorithm, publicKey, this.signature, this.tbs);
  }
}