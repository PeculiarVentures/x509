import {
  AsnChoiceType,
  AsnConvert,
  AsnIntegerArrayBufferConverter,
  AsnProp,
  AsnPropTypes,
  OctetString,
} from "@peculiar/asn1-schema";
import {
  AlgorithmIdentifier,
  Certificate,
  Extension as AsnExtension,
  Name,
} from "@peculiar/asn1-x509";

export const id_pkix_ocsp_basic = "1.3.6.1.5.5.7.48.1.1";
export const id_pkix_ocsp_nonce = "1.3.6.1.5.5.7.48.1.2";

export enum OcspResponseStatus {
  successful = 0,
  malformedRequest = 1,
  internalError = 2,
  tryLater = 3,
  sigRequired = 5,
  unauthorized = 6,
}

/**
 * ```asn1
 * CertID ::= SEQUENCE {
 *   hashAlgorithm            AlgorithmIdentifier,
 *   issuerNameHash           OCTET STRING,
 *   issuerKeyHash            OCTET STRING,
 *   serialNumber             CertificateSerialNumber }
 * ```
 */
export class CertID {
  @AsnProp({ type: AlgorithmIdentifier })
  public hashAlgorithm: AlgorithmIdentifier = new AlgorithmIdentifier();

  @AsnProp({ type: AsnPropTypes.OctetString })
  public issuerNameHash: ArrayBuffer = new ArrayBuffer(0);

  @AsnProp({ type: AsnPropTypes.OctetString })
  public issuerKeyHash: ArrayBuffer = new ArrayBuffer(0);

  @AsnProp({
    type: AsnPropTypes.Integer,
    converter: AsnIntegerArrayBufferConverter,
  })
  public serialNumber: ArrayBuffer = new ArrayBuffer(0);

  public constructor(params: Partial<CertID> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * Request ::= SEQUENCE {
 *   reqCert                     CertID,
 *   singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
 * ```
 */
export class OcspRequestItem {
  @AsnProp({ type: CertID })
  public reqCert: CertID = new CertID();

  @AsnProp({
    type: AsnExtension,
    context: 0,
    optional: true,
    repeated: "sequence",
  })
  public singleRequestExtensions?: AsnExtension[];

  public constructor(params: Partial<OcspRequestItem> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * TBSRequest ::= SEQUENCE {
 *   version             [0] EXPLICIT Version DEFAULT v1,
 *   requestList             SEQUENCE OF Request,
 *   requestExtensions       [2] EXPLICIT Extensions OPTIONAL }
 * ```
 */
export class TBSRequest {
  @AsnProp({
    type: AsnPropTypes.Integer,
    context: 0,
    defaultValue: 0,
  })
  public version = 0;

  @AsnProp({ type: OcspRequestItem, repeated: "sequence" })
  public requestList: OcspRequestItem[] = [];

  @AsnProp({
    type: AsnExtension,
    context: 2,
    optional: true,
    repeated: "sequence",
  })
  public requestExtensions?: AsnExtension[];

  public constructor(params: Partial<TBSRequest> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * Signature ::= SEQUENCE {
 *   signatureAlgorithm      AlgorithmIdentifier,
 *   signature               BIT STRING,
 *   certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 * ```
 */
export class OcspSignature {
  @AsnProp({ type: AlgorithmIdentifier })
  public signatureAlgorithm: AlgorithmIdentifier = new AlgorithmIdentifier();

  @AsnProp({ type: AsnPropTypes.BitString })
  public signature: ArrayBuffer = new ArrayBuffer(0);

  @AsnProp({
    type: Certificate,
    context: 0,
    optional: true,
    repeated: "sequence",
  })
  public certs?: Certificate[];

  public constructor(params: Partial<OcspSignature> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * OCSPRequest ::= SEQUENCE {
 *   tbsRequest                  TBSRequest,
 *   optionalSignature       [0] EXPLICIT Signature OPTIONAL }
 * ```
 */
export class OCSPRequest {
  @AsnProp({ type: TBSRequest, raw: true })
  public tbsRequest: TBSRequest = new TBSRequest();

  public tbsRequestRaw?: ArrayBuffer;

  @AsnProp({ type: OcspSignature, context: 0, optional: true })
  public optionalSignature?: OcspSignature;

  public constructor(params: Partial<OCSPRequest> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * ResponseBytes ::= SEQUENCE {
 *   responseType               OBJECT IDENTIFIER,
 *   response                   OCTET STRING }
 * ```
 */
export class ResponseBytes {
  @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
  public responseType = "";

  @AsnProp({ type: AsnPropTypes.OctetString })
  public response: ArrayBuffer = new ArrayBuffer(0);

  public constructor(params: Partial<ResponseBytes> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * OCSPResponse ::= SEQUENCE {
 *   responseStatus         OCSPResponseStatus,
 *   responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
 * ```
 */
export class OCSPResponse {
  @AsnProp({ type: AsnPropTypes.Enumerated })
  public responseStatus: OcspResponseStatus = OcspResponseStatus.successful;

  @AsnProp({ type: ResponseBytes, context: 0, optional: true })
  public responseBytes?: ResponseBytes;

  public constructor(params: Partial<OCSPResponse> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * ResponderID ::= CHOICE {
 *   byName              [1] EXPLICIT Name,
 *   byKey               [2] EXPLICIT KeyHash }
 * KeyHash ::= OCTET STRING
 * ```
 */
@AsnChoiceType()
export class ResponderID {
  @AsnProp({ type: Name, context: 1 })
  public byName?: Name;

  @AsnProp({ type: AsnPropTypes.OctetString, context: 2 })
  public byKey?: ArrayBuffer;

  public constructor(params: Partial<ResponderID> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * RevokedInfo ::= SEQUENCE {
 *   revocationTime              GeneralizedTime,
 *   revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
 * ```
 */
export class RevokedInfo {
  @AsnProp({ type: AsnPropTypes.GeneralizedTime })
  public revocationTime: Date = new Date();

  @AsnProp({
    type: AsnPropTypes.Enumerated,
    context: 0,
    optional: true,
  })
  public revocationReason?: number;

  public constructor(params: Partial<RevokedInfo> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * CertStatus ::= CHOICE {
 *   good                [0]     IMPLICIT NULL,
 *   revoked             [1]     IMPLICIT RevokedInfo,
 *   unknown             [2]     IMPLICIT NULL }
 * ```
 */
@AsnChoiceType()
export class CertStatus {
  @AsnProp({
    type: AsnPropTypes.Null,
    context: 0,
    implicit: true,
  })
  public good?: null;

  @AsnProp({
    type: RevokedInfo,
    context: 1,
    implicit: true,
  })
  public revoked?: RevokedInfo;

  @AsnProp({
    type: AsnPropTypes.Null,
    context: 2,
    implicit: true,
  })
  public unknown?: null;

  public constructor(params: Partial<CertStatus> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * SingleResponse ::= SEQUENCE {
 *   certID                       CertID,
 *   certStatus                   CertStatus,
 *   thisUpdate                   GeneralizedTime,
 *   nextUpdate           [0]     EXPLICIT GeneralizedTime OPTIONAL,
 *   singleExtensions     [1]     EXPLICIT Extensions OPTIONAL }
 * ```
 */
export class SingleResponse {
  @AsnProp({ type: CertID })
  public certID: CertID = new CertID();

  @AsnProp({ type: CertStatus })
  public certStatus: CertStatus = new CertStatus();

  @AsnProp({ type: AsnPropTypes.GeneralizedTime })
  public thisUpdate: Date = new Date();

  @AsnProp({
    type: AsnPropTypes.GeneralizedTime,
    context: 0,
    optional: true,
  })
  public nextUpdate?: Date;

  @AsnProp({
    type: AsnExtension,
    context: 1,
    optional: true,
    repeated: "sequence",
  })
  public singleExtensions?: AsnExtension[];

  public constructor(params: Partial<SingleResponse> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * ResponseData ::= SEQUENCE {
 *   version              [0] EXPLICIT Version DEFAULT v1,
 *   responderID              ResponderID,
 *   producedAt               GeneralizedTime,
 *   responses                SEQUENCE OF SingleResponse,
 *   responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 * ```
 */
export class ResponseData {
  @AsnProp({
    type: AsnPropTypes.Integer,
    context: 0,
    defaultValue: 0,
  })
  public version = 0;

  @AsnProp({ type: ResponderID })
  public responderID: ResponderID = new ResponderID();

  @AsnProp({ type: AsnPropTypes.GeneralizedTime })
  public producedAt: Date = new Date();

  @AsnProp({ type: SingleResponse, repeated: "sequence" })
  public responses: SingleResponse[] = [];

  @AsnProp({
    type: AsnExtension,
    context: 1,
    optional: true,
    repeated: "sequence",
  })
  public responseExtensions?: AsnExtension[];

  public constructor(params: Partial<ResponseData> = {}) {
    Object.assign(this, params);
  }
}

/**
 * ```asn1
 * BasicOCSPResponse ::= SEQUENCE {
 *   tbsResponseData      ResponseData,
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signature            BIT STRING,
 *   certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 * ```
 */
export class BasicOCSPResponse {
  @AsnProp({ type: ResponseData, raw: true })
  public tbsResponseData: ResponseData = new ResponseData();

  public tbsResponseDataRaw?: ArrayBuffer;

  @AsnProp({ type: AlgorithmIdentifier })
  public signatureAlgorithm: AlgorithmIdentifier = new AlgorithmIdentifier();

  @AsnProp({ type: AsnPropTypes.BitString })
  public signature: ArrayBuffer = new ArrayBuffer(0);

  @AsnProp({
    type: Certificate,
    context: 0,
    optional: true,
    repeated: "sequence",
  })
  public certs?: Certificate[];

  public constructor(params: Partial<BasicOCSPResponse> = {}) {
    Object.assign(this, params);
  }
}

export { AsnConvert, OctetString };
export type { AsnExtension };
