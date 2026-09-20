import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
  Certificate,
  CRLReason,
  CRLReasons,
  Extension as AsnExtension,
  Name as AsnName,
} from "@peculiar/asn1-x509";
import { container } from "tsyringe";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { diAsnSignatureFormatter, IAsnSignatureFormatter } from "../asn_signature_formatter";
import { Extension } from "../extension";
import { cryptoProvider } from "../provider";
import { HashedAlgorithm } from "../types";
import { X509Certificate } from "../x509_cert";
import {
  BasicOCSPResponse,
  CertID,
  CertStatus,
  id_pkix_ocsp_basic,
  OCSPResponse,
  OCSPResponseStatus,
  ResponderID,
  ResponseBytes,
  ResponseData,
  RevokedInfo,
  SingleResponse,
  Version,
} from "@peculiar/asn1-ocsp";
import { OcspSingleStatus, OcspResponse } from "./ocsp_response";
import { OcspCertId } from "./ocsp_cert_id";

export interface BasicOcspSingleResponseParams {
  certId: OcspCertId;
  status: OcspSingleStatus;
  revocationTime?: Date;
  revocationReason?: number;
  thisUpdate: Date;
  nextUpdate?: Date;
  singleExtensions?: Extension[];
}

export interface BasicOcspResponseCreateParams {
  issuer: X509Certificate;
  responderCert?: X509Certificate;
  signingKey: CryptoKey;
  producedAt?: Date;
  responses: BasicOcspSingleResponseParams[];
  responseExtensions?: Extension[];
  signingAlgorithm?: Algorithm | EcdsaParams;
}

/**
 * Generator of BasicOCSPResponse and OCSPResponse
 */
export class BasicOcspResponseGenerator {
  /**
   * Creates an OCSP response signed by private key
   * @param params Create parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async create(
    params: BasicOcspResponseCreateParams,
    crypto = cryptoProvider.get(),
  ): Promise<OcspResponse> {
    const producedAt = params.producedAt || new Date();

    const responderName = params.responderCert
      ? params.responderCert.subjectName
      : params.issuer.subjectName;
    const asnResponderName = AsnConvert.parse(responderName.toArrayBuffer(), AsnName);
    const responderID = new ResponderID({
      byName: asnResponderName,
    });

    const singles: SingleResponse[] = [];
    for (const item of params.responses) {
      const certStatus = new CertStatus();
      if (item.status === "good") {
        certStatus.good = null;
      } else if (item.status === "revoked") {
        certStatus.revoked = new RevokedInfo({
          revocationTime: item.revocationTime || item.thisUpdate,
          revocationReason:
            item.revocationReason === undefined
              ? undefined
              : new CRLReason(item.revocationReason as CRLReasons),
        });
      } else {
        certStatus.unknown = null;
      }

      const single = new SingleResponse({
        certID: AsnConvert.parse(item.certId.rawData, CertID),
        certStatus,
        thisUpdate: item.thisUpdate,
        nextUpdate: item.nextUpdate,
      });
      if (item.singleExtensions?.length) {
        single.singleExtensions = item.singleExtensions.map((o) =>
          AsnConvert.parse(o.rawData, AsnExtension),
        );
      }
      singles.push(single);
    }

    const responseData = new ResponseData({
      version: Version.v1,
      responderID,
      producedAt,
      responses: singles,
    });
    if (params.responseExtensions?.length) {
      responseData.responseExtensions = params.responseExtensions.map((o) =>
        AsnConvert.parse(o.rawData, AsnExtension),
      );
    }

    const defaultSigningAlgorithm = { hash: "SHA-256" };
    const signingAlgorithm = {
      ...defaultSigningAlgorithm,
      ...params.signingAlgorithm,
      ...params.signingKey.algorithm,
    } as HashedAlgorithm;

    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    const asnSignatureAlgorithm = algProv.toAsnAlgorithm(signingAlgorithm);

    const tbs = AsnConvert.serialize(responseData);
    const signature = await crypto.subtle.sign(signingAlgorithm, params.signingKey, tbs);

    const signatureFormatters = container
      .resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter)
      .reverse();
    let asnSignature: ArrayBuffer | null = null;
    for (const formatter of signatureFormatters) {
      asnSignature = formatter.toAsnSignature(signingAlgorithm, signature);
      if (asnSignature) {
        break;
      }
    }
    if (!asnSignature) {
      throw new Error("Cannot convert ASN.1 signature value to WebCrypto format");
    }

    const basic = new BasicOCSPResponse({
      tbsResponseData: responseData,
      signatureAlgorithm: asnSignatureAlgorithm,
      signature: asnSignature,
    });
    if (params.responderCert) {
      const asnCert = AsnConvert.parse(params.responderCert.rawData, Certificate);
      basic.certs = [asnCert];
    }

    const basicDer = AsnConvert.serialize(basic);
    const response = new OCSPResponse({
      responseStatus: OCSPResponseStatus.successful,
      responseBytes: new ResponseBytes({
        responseType: id_pkix_ocsp_basic,
        response: new OctetString(basicDer),
      }),
    });

    return new OcspResponse(response);
  }

  /**
   * Creates a non-successful OCSP response with given status
   * @param status Response status (must not be successful)
   */
  public static createError(status: OCSPResponseStatus): OcspResponse {
    if ((status as OCSPResponseStatus) === OCSPResponseStatus.successful) {
      throw new Error("Status must not be successful for error responses");
    }

    return new OcspResponse(
      new OCSPResponse({
        responseStatus: status,
      }),
    );
  }
}
