import { AsnConvert } from "@peculiar/asn1-schema";
import { Extension as AsnExtension } from "@peculiar/asn1-x509";
import { Extension } from "../extension";
import { AsnEncodedType, PemData } from "../pem_data";
import { cryptoProvider } from "../provider";
import { PemConverter } from "../pem_converter";
import { ParseOptions } from "../types";
import { X509Certificate } from "../x509_cert";
import { CertID, OCSPRequest, OcspRequestItem, TBSRequest } from "./asn";
import { createOcspNonceExtension, getOcspNonce } from "./nonce";
import { OcspCertId, OcspHashAlgorithm } from "./ocsp_cert_id";

export interface OcspRequestCreateParams {
  /**
   * Issuer certificate
   */
  issuer: X509Certificate;
  /**
   * Target certificates to check
   */
  certificates: X509Certificate[];
  /**
   * Hash algorithm for CertID. Default is SHA-256
   */
  hashAlgorithm?: OcspHashAlgorithm;
  /**
   * Nonce value. `true` generates 16 random bytes, `false` or `undefined` omits nonce,
   * BufferSource uses given value. Default is `true`
   */
  nonce?: boolean | BufferSource;
  /**
   * Additional request extensions (nonce is added automatically)
   */
  requestExtensions?: Extension[];
}

/**
 * Representation of OCSP Request
 */
export class OcspRequest extends PemData<OCSPRequest> {
  public static override NAME = "OCSP Request";

  protected readonly tag = PemConverter.OcspRequestTag;

  #requests?: OcspCertId[];
  #extensions?: Extension[];
  #nonce?: ArrayBuffer | undefined;
  #nonceLoaded = false;

  /**
   * Gets a list of CertIDs
   */
  public get requests(): OcspCertId[] {
    if (!this.#requests) {
      this.#requests = this.asn.tbsRequest.requestList.map(
        (o) => new OcspCertId(o.reqCert, this.parseOptions),
      );
    }

    return this.#requests;
  }

  /**
   * Gets a list of request extensions
   */
  public get extensions(): Extension[] {
    if (!this.#extensions) {
      this.#extensions = [];
      if (this.asn.tbsRequest.requestExtensions) {
        this.#extensions = this.asn.tbsRequest.requestExtensions.map(
          (o) => new Extension(AsnConvert.serialize(o), this.parseOptions),
        );
      }
    }

    return this.#extensions;
  }

  /**
   * Gets a nonce value or undefined
   */
  public get nonce(): ArrayBuffer | undefined {
    if (!this.#nonceLoaded) {
      this.#nonce = getOcspNonce(this.extensions);
      this.#nonceLoaded = true;
    }

    return this.#nonce;
  }

  /**
   * Creates a new instance from ASN.1 OCSPRequest object
   * @param asn ASN.1 OCSPRequest object
   * @param options Optional ASN.1 parse options
   */
  public constructor(asn: OCSPRequest, options?: ParseOptions);
  /**
   * Creates a new instance
   * @param raw Encoded buffer (DER, PEM, HEX, Base64, Base64Url)
   * @param options Optional ASN.1 parse options
   */
  public constructor(raw: AsnEncodedType, options?: ParseOptions);
  public constructor(param: AsnEncodedType | OCSPRequest, options?: ParseOptions) {
    const args = PemData.isAsnEncoded(param) ? [param, OCSPRequest, options] : [param, options];
    super(args[0] as any, args[1] as any, args[2] as any);
  }

  protected onInit(_asn: OCSPRequest): void {
    // Initialization is now lazy
  }

  /**
   * Creates an OCSP request
   * @param params Create parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async create(params: OcspRequestCreateParams, crypto = cryptoProvider.get()) {
    const hashAlgorithm = params.hashAlgorithm || "SHA-256";

    const requestList: OcspRequestItem[] = [];
    for (const target of params.certificates) {
      const certId = await OcspCertId.create(params.issuer, target, hashAlgorithm, crypto);
      requestList.push(
        new OcspRequestItem({
          reqCert: AsnConvert.parse(certId.rawData, CertID),
        }),
      );
    }

    const extensions: Extension[] = [...(params.requestExtensions || [])];

    let nonce = params.nonce;
    if (nonce === undefined) {
      nonce = true;
    }
    if (nonce === true) {
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      extensions.push(createOcspNonceExtension(bytes));
    } else if (nonce !== false) {
      extensions.push(createOcspNonceExtension(nonce as BufferSource));
    }

    const tbs = new TBSRequest({
      version: 0,
      requestList,
    });
    if (extensions.length) {
      tbs.requestExtensions = extensions.map((o) => AsnConvert.parse(o.rawData, AsnExtension));
    }

    const asn = new OCSPRequest({
      tbsRequest: tbs,
    });

    return new OcspRequest(asn);
  }

  /**
   * Returns an extension of specified type
   * @param type Extension identifier
   */
  public getExtension(type: string): Extension | null {
    for (const ext of this.extensions) {
      if (ext.type === type) {
        return ext;
      }
    }

    return null;
  }
}
