import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import { BufferSourceConverter, isEqual } from "pvtsutils";
import { container } from "tsyringe";
import { AsnData } from "../asn_data";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { diAsnSignatureFormatter, IAsnSignatureFormatter } from "../asn_signature_formatter";
import { Extension } from "../extension";
import { ExtendedKeyUsageExtension } from "../extensions/extended_key_usage";
import { Name } from "../name";
import { AsnEncodedType, PemData } from "../pem_data";
import { PemConverter } from "../pem_converter";
import { cryptoProvider } from "../provider";
import { PublicKey } from "../public_key";
import { HashedAlgorithm, ParseOptions } from "../types";
import { X509Certificate } from "../x509_cert";
import {
  BasicOCSPResponse,
  id_pkix_ocsp_basic,
  OCSPResponse,
  OCSPResponseStatus,
  SingleResponse,
} from "@peculiar/asn1-ocsp";
import { OcspResponseStatusError, OcspVerifyError } from "./errors";
import { getOcspNonce } from "./nonce";
import { OcspCertId } from "./ocsp_cert_id";
import { OcspRequest } from "./ocsp_request";

export type OcspSingleStatus = "good" | "revoked" | "unknown";

export interface OcspResponseVerifyParams {
  /**
   * Issuer certificate
   */
  issuer: X509Certificate;
  /**
   * Responder certificate for delegated responses. If omitted, uses certs from response
   */
  responder?: X509Certificate;
  /**
   * Original request for nonce and CertID binding checks
   */
  request?: OcspRequest;
  /**
   * Verification date. Default is current date
   */
  date?: Date;
  /**
   * Clock skew tolerance in seconds. Default is 300
   */
  clockSkew?: number;
}

export interface OcspSingleResult {
  certId: OcspCertId;
  status: OcspSingleStatus;
  revocationTime?: Date;
  revocationReason?: number;
  thisUpdate: Date;
  nextUpdate?: Date;
  producedAt: Date;
  nonceMatched: boolean;
}

/**
 * Representation of OCSP SingleResponse
 */
export class OcspSingleResponse extends AsnData<SingleResponse> {
  #certId?: OcspCertId;
  #status?: OcspSingleStatus;
  #extensions?: Extension[];

  /**
   * Gets a CertID
   */
  public get certId(): OcspCertId {
    if (!this.#certId) {
      this.#certId = new OcspCertId(this.asn.certID, this.parseOptions);
    }

    return this.#certId;
  }

  /**
   * Gets a certificate status
   */
  public get status(): OcspSingleStatus {
    if (!this.#status) {
      if (this.asn.certStatus.revoked !== undefined) {
        this.#status = "revoked";
      } else if (this.asn.certStatus.unknown !== undefined) {
        this.#status = "unknown";
      } else {
        this.#status = "good";
      }
    }

    return this.#status;
  }

  /**
   * Gets a revocation time for revoked certificates
   */
  public get revocationTime(): Date | undefined {
    return this.asn.certStatus.revoked?.revocationTime;
  }

  /**
   * Gets a revocation reason for revoked certificates
   */
  public get revocationReason(): number | undefined {
    const reason = this.asn.certStatus.revoked?.revocationReason;

    return reason === undefined ? undefined : reason.reason;
  }

  /**
   * Gets thisUpdate date
   */
  public get thisUpdate(): Date {
    return this.asn.thisUpdate;
  }

  /**
   * Gets nextUpdate date
   */
  public get nextUpdate(): Date | undefined {
    return this.asn.nextUpdate;
  }

  /**
   * Gets single extensions
   */
  public get extensions(): Extension[] {
    if (!this.#extensions) {
      this.#extensions = [];
      if (this.asn.singleExtensions) {
        this.#extensions = this.asn.singleExtensions.map(
          (o) => new Extension(AsnConvert.serialize(o), this.parseOptions),
        );
      }
    }

    return this.#extensions;
  }

  /**
   * Creates a new instance from ASN.1 SingleResponse object
   * @param asn ASN.1 SingleResponse object
   * @param options Optional ASN.1 parse options
   */
  public constructor(asn: SingleResponse, options?: ParseOptions);
  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   * @param options Optional ASN.1 parse options
   */
  public constructor(raw: BufferSource, options?: ParseOptions);
  public constructor(param: BufferSource | SingleResponse, options?: ParseOptions) {
    const args = BufferSourceConverter.isBufferSource(param)
      ? [param, SingleResponse, options]
      : [param, options];
    super(args[0] as any, args[1] as any, args[2] as any);
  }

  protected onInit(_asn: SingleResponse): void {
    // Initialization is now lazy
  }
}

export type OcspResponderId =
  | { type: "byName"; value: Name }
  | { type: "byKey"; value: ArrayBuffer };

/**
 * Representation of BasicOCSPResponse
 */
export class BasicOcspResponse extends AsnData<BasicOCSPResponse> {
  public static override NAME = "Basic OCSP Response";

  #responderId?: OcspResponderId;
  #responses?: OcspSingleResponse[];
  #certs?: X509Certificate[];
  #extensions?: Extension[];
  #nonce?: ArrayBuffer | undefined;
  #nonceLoaded = false;
  #signatureAlgorithm?: HashedAlgorithm;
  #tbs?: ArrayBuffer;

  /**
   * Gets a responder ID
   */
  public get responderId(): OcspResponderId {
    if (!this.#responderId) {
      const asn = this.asn.tbsResponseData.responderID;
      if (asn.byName) {
        this.#responderId = { type: "byName", value: new Name(asn.byName) };
      } else if (asn.byKey) {
        this.#responderId = { type: "byKey", value: asn.byKey.buffer };
      } else {
        throw new Error("Cannot get responder ID. ResponderID is empty");
      }
    }

    return this.#responderId;
  }

  /**
   * Gets producedAt date
   */
  public get producedAt(): Date {
    return this.asn.tbsResponseData.producedAt;
  }

  /**
   * Gets a list of single responses
   */
  public get responses(): OcspSingleResponse[] {
    if (!this.#responses) {
      this.#responses = this.asn.tbsResponseData.responses.map(
        (o) => new OcspSingleResponse(o, this.parseOptions),
      );
    }

    return this.#responses;
  }

  /**
   * Gets a list of certificates included in response
   */
  public get certs(): X509Certificate[] {
    if (!this.#certs) {
      this.#certs = [];
      if (this.asn.certs) {
        this.#certs = this.asn.certs.map((o) => new X509Certificate(o, this.parseOptions));
      }
    }

    return this.#certs;
  }

  /**
   * Gets a list of response extensions
   */
  public get extensions(): Extension[] {
    if (!this.#extensions) {
      this.#extensions = [];
      if (this.asn.tbsResponseData.responseExtensions) {
        this.#extensions = this.asn.tbsResponseData.responseExtensions.map(
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
   * Gets a signature algorithm
   */
  public get signatureAlgorithm(): HashedAlgorithm {
    if (!this.#signatureAlgorithm) {
      const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
      this.#signatureAlgorithm = algProv.toWebAlgorithm(
        this.asn.signatureAlgorithm,
      ) as HashedAlgorithm;
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
   * Gets the ToBeSigned block
   */
  private get tbs(): ArrayBuffer {
    if (!this.#tbs) {
      this.#tbs = this.asn.tbsResponseDataRaw || AsnConvert.serialize(this.asn.tbsResponseData);
    }

    return this.#tbs;
  }

  /**
   * Creates a new instance from ASN.1 BasicOCSPResponse object
   * @param asn ASN.1 BasicOCSPResponse object
   * @param options Optional ASN.1 parse options
   */
  public constructor(asn: BasicOCSPResponse, options?: ParseOptions);
  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   * @param options Optional ASN.1 parse options
   */
  public constructor(raw: BufferSource, options?: ParseOptions);
  public constructor(param: BufferSource | BasicOCSPResponse, options?: ParseOptions) {
    const args = BufferSourceConverter.isBufferSource(param)
      ? [param, BasicOCSPResponse, options]
      : [param, options];
    super(args[0] as any, args[1] as any, args[2] as any);
  }

  protected onInit(_asn: BasicOCSPResponse): void {
    // Initialization is now lazy
  }

  /**
   * Validates a BasicOCSPResponse signature
   * @param publicKey Public key for verification
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async verifySignature(
    publicKey: X509Certificate | PublicKey | CryptoKey,
    crypto = cryptoProvider.get(),
  ): Promise<boolean> {
    let keyAlgorithm: Algorithm;
    let key: CryptoKey;
    try {
      if (publicKey instanceof X509Certificate) {
        keyAlgorithm = {
          ...publicKey.publicKey.algorithm,
          ...this.signatureAlgorithm,
        };
        key = await publicKey.publicKey.export(keyAlgorithm, ["verify"], crypto);
      } else if (publicKey instanceof PublicKey) {
        keyAlgorithm = {
          ...publicKey.algorithm,
          ...this.signatureAlgorithm,
        };
        key = await publicKey.export(keyAlgorithm, ["verify"], crypto);
      } else {
        keyAlgorithm = {
          ...publicKey.algorithm,
          ...this.signatureAlgorithm,
        };
        key = publicKey;
      }
    } catch {
      return false;
    }

    const signatureFormatters = container
      .resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter)
      .reverse();
    let signature: ArrayBuffer | null = null;
    for (const formatter of signatureFormatters) {
      signature = formatter.toWebSignature(keyAlgorithm, this.signature);
      if (signature) {
        break;
      }
    }
    if (!signature) {
      throw new Error("Cannot convert ASN.1 signature value to WebCrypto format");
    }

    return crypto.subtle.verify(this.signatureAlgorithm, key, signature, this.tbs);
  }

  /**
   * Returns a single response for specified CertID
   * @param certId CertID
   */
  public getSingle(certId: OcspCertId): OcspSingleResponse | null {
    for (const single of this.responses) {
      if (single.certId.equal(certId)) {
        return single;
      }
    }

    return null;
  }
}

/**
 * Representation of OCSP Response
 */
export class OcspResponse extends PemData<OCSPResponse> {
  public static override NAME = "OCSP Response";

  protected readonly tag = PemConverter.OcspResponseTag;

  #basic?: BasicOcspResponse | null;
  #basicLoaded = false;

  /**
   * Gets a response status
   */
  public get status(): OCSPResponseStatus {
    return this.asn.responseStatus;
  }

  /**
   * Gets a BasicOCSPResponse for successful responses
   */
  public get basic(): BasicOcspResponse | undefined {
    if (!this.#basicLoaded) {
      this.#basicLoaded = true;
      if (this.asn.responseBytes && this.asn.responseBytes.responseType === id_pkix_ocsp_basic) {
        this.#basic = new BasicOcspResponse(this.asn.responseBytes.response, this.parseOptions);
      } else {
        this.#basic = null;
      }
    }

    return this.#basic || undefined;
  }

  /**
   * Creates a new instance from ASN.1 OCSPResponse object
   * @param asn ASN.1 OCSPResponse object
   * @param options Optional ASN.1 parse options
   */
  public constructor(asn: OCSPResponse, options?: ParseOptions);
  /**
   * Creates a new instance
   * @param raw Encoded buffer (DER, PEM, HEX, Base64, Base64Url)
   * @param options Optional ASN.1 parse options
   */
  public constructor(raw: AsnEncodedType, options?: ParseOptions);
  public constructor(param: AsnEncodedType | OCSPResponse, options?: ParseOptions) {
    const args = PemData.isAsnEncoded(param) ? [param, OCSPResponse, options] : [param, options];
    super(args[0] as any, args[1] as any, args[2] as any);
  }

  protected onInit(_asn: OCSPResponse): void {
    // Initialization is now lazy
  }

  /**
   * Returns a single response for specified CertID
   * @param certId CertID
   */
  public getSingle(certId: OcspCertId): OcspSingleResponse | null {
    return this.basic?.getSingle(certId) || null;
  }

  /**
   * Validates an OCSP response and returns single results
   * @param params Verification parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async verify(
    params: OcspResponseVerifyParams,
    crypto = cryptoProvider.get(),
  ): Promise<OcspSingleResult[]> {
    if (this.status !== OCSPResponseStatus.successful) {
      throw new OcspResponseStatusError(this.status);
    }

    const basic = this.basic;
    if (!basic) {
      if (this.asn.responseBytes && this.asn.responseBytes.responseType !== id_pkix_ocsp_basic) {
        throw new OcspVerifyError("responder", "Unsupported OCSP response type");
      }
      throw new OcspVerifyError("responder", "OCSP response does not contain BasicOCSPResponse");
    }

    const date = params.date || new Date();
    const clockSkew = (params.clockSkew ?? 300) * 1000;

    const issuer = params.issuer;
    const responderId = basic.responderId;

    const direct = await isDirectResponder(responderId, issuer, crypto);

    let verifyKey: X509Certificate | PublicKey | CryptoKey;
    let responderCert: X509Certificate | undefined;

    if (direct) {
      verifyKey = issuer;
    } else {
      responderCert = params.responder || findResponderCert(basic, responderId);
      if (!responderCert) {
        throw new OcspVerifyError("responder", "Cannot find responder certificate");
      }
      const matched = await matchesResponderId(responderCert, responderId, crypto);
      if (!matched) {
        throw new OcspVerifyError("responder", "Responder certificate does not match responder ID");
      }
      verifyKey = responderCert;
    }

    const sigOk = await basic.verifySignature(verifyKey, crypto);
    if (!sigOk) {
      throw new OcspVerifyError("signature", "Invalid OCSP response signature");
    }

    // This one-link responder authorization is temporary. It will move to the
    // future certificate chain validator, which will own full validation of the
    // responder chain up to a trust anchor. Note the current leniency: a delegated
    // responder without an EKU extension is allowed here, while strict RFC 6960
    // would require id-kp-OCSPSigning in that case.
    if (!direct) {
      if (!responderCert) {
        throw new OcspVerifyError("responder", "Cannot find responder certificate");
      }
      if (responderCert.issuer !== issuer.subject) {
        throw new OcspVerifyError(
          "authorization",
          "Responder certificate is not issued by the issuer",
        );
      }
      const certOk = await responderCert.verify({ publicKey: issuer, date });
      if (!certOk) {
        throw new OcspVerifyError(
          "authorization",
          "Responder certificate signature or validity check failed",
        );
      }
      const eku = responderCert.getExtension(ExtendedKeyUsageExtension);
      if (eku && !eku.usages.includes("1.3.6.1.5.5.7.3.9")) {
        throw new OcspVerifyError(
          "authorization",
          "Responder certificate is not authorized for OCSP signing",
        );
      }
    }

    if (basic.producedAt.getTime() > date.getTime() + clockSkew) {
      throw new OcspVerifyError("freshness", "OCSP response producedAt is in the future");
    }

    let nonceMatched = false;
    if (params.request?.nonce) {
      const reqNonce = params.request.nonce;
      const respNonce = basic.nonce;
      if (!respNonce || !isEqual(reqNonce, respNonce)) {
        throw new OcspVerifyError("nonce", "OCSP response nonce does not match request nonce");
      }
      nonceMatched = true;
    }

    const results: OcspSingleResult[] = [];
    for (const single of basic.responses) {
      await assertCertId(single.certId, issuer, crypto);

      if (params.request && params.request.requests.length) {
        const found = params.request.requests.some((o) => o.equal(single.certId));
        if (!found) {
          throw new OcspVerifyError("certId", "OCSP single CertID does not match request");
        }
      }

      const thisUpdate = single.thisUpdate.getTime();
      const nextUpdate = single.nextUpdate?.getTime();
      if (thisUpdate > date.getTime() + clockSkew) {
        throw new OcspVerifyError("freshness", "OCSP single thisUpdate is in the future");
      }
      if (nextUpdate !== undefined && nextUpdate <= date.getTime() - clockSkew) {
        throw new OcspVerifyError("freshness", "OCSP single response is expired");
      }

      results.push({
        certId: single.certId,
        status: single.status,
        revocationTime: single.revocationTime,
        revocationReason: single.revocationReason,
        thisUpdate: single.thisUpdate,
        nextUpdate: single.nextUpdate,
        producedAt: basic.producedAt,
        nonceMatched,
      });
    }

    return results;
  }
}

async function getIssuerKeyHash(issuer: X509Certificate, crypto: Crypto): Promise<ArrayBuffer> {
  const spki = AsnConvert.parse(issuer.publicKey.rawData, SubjectPublicKeyInfo);

  return crypto.subtle.digest("SHA-1", spki.subjectPublicKey);
}

async function isDirectResponder(
  responderId: OcspResponderId,
  issuer: X509Certificate,
  crypto: Crypto,
): Promise<boolean> {
  if (responderId.type === "byName") {
    const responderNameDer = responderId.value.toArrayBuffer();
    const issuerNameDer = issuer.subjectName.toArrayBuffer();

    return isEqual(responderNameDer, issuerNameDer);
  }
  if (responderId.type === "byKey") {
    const ski = await getIssuerKeyHash(issuer, crypto);

    return isEqual(responderId.value, ski);
  }

  return false;
}

async function matchesResponderId(
  cert: X509Certificate,
  responderId: OcspResponderId,
  crypto: Crypto,
): Promise<boolean> {
  if (responderId.type === "byName") {
    const responderNameDer = responderId.value.toArrayBuffer();
    const certNameDer = cert.subjectName.toArrayBuffer();

    return isEqual(responderNameDer, certNameDer);
  }
  if (responderId.type === "byKey") {
    const ski = await getIssuerKeyHash(cert, crypto);

    return isEqual(responderId.value, ski);
  }

  return false;
}

function findResponderCert(
  basic: BasicOcspResponse,
  responderId: OcspResponderId,
): X509Certificate | undefined {
  if (basic.certs.length === 1) {
    return basic.certs[0];
  }
  for (const cert of basic.certs) {
    if (responderId.type === "byName") {
      const responderNameDer = responderId.value.toArrayBuffer();
      const certNameDer = cert.subjectName.toArrayBuffer();
      if (isEqual(responderNameDer, certNameDer)) {
        return cert;
      }
    } else {
      // byKey match requires async digest; fall back to first cert here.
      // Exact byKey matching is enforced in matchesResponderId during verify.
      continue;
    }
  }

  return basic.certs[0];
}

async function assertCertId(
  certId: OcspCertId,
  issuer: X509Certificate,
  crypto: Crypto,
): Promise<void> {
  const hashName = "name" in certId.hashAlgorithm ? (certId.hashAlgorithm as Algorithm).name : "";
  if (!hashName) {
    throw new OcspVerifyError("certId", "Unsupported CertID hash algorithm");
  }

  const issuerNameDer = issuer.subjectName.toArrayBuffer();
  const spki = AsnConvert.parse(issuer.publicKey.rawData, SubjectPublicKeyInfo);
  const issuerKeyBytes = spki.subjectPublicKey;

  let expectedNameHash: ArrayBuffer;
  let expectedKeyHash: ArrayBuffer;
  try {
    expectedNameHash = await crypto.subtle.digest(hashName, issuerNameDer);
    expectedKeyHash = await crypto.subtle.digest(hashName, issuerKeyBytes);
  } catch {
    throw new OcspVerifyError("certId", "Unsupported CertID hash algorithm");
  }

  if (
    !isEqual(expectedNameHash, certId.issuerNameHash) ||
    !isEqual(expectedKeyHash, certId.issuerKeyHash)
  ) {
    throw new OcspVerifyError("certId", "OCSP single CertID does not match issuer");
  }
}
