import * as ocsp from "@peculiar/asn1-ocsp";
import * as asn1X509 from "@peculiar/asn1-x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { container } from "tsyringe";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { Extension } from "../extension";
import { cryptoProvider } from "../provider";
import { X509Certificate } from "../x509_cert";
import { OCSPRequest } from "./ocsp_request";
import { OCSPResponse, OCSPResponseStatus } from "./ocsp_response";
import { IAsnSignatureFormatter, diAsnSignatureFormatter } from "../asn_signature_formatter";
import { HashedAlgorithm } from "../types";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { PublicKey } from "../public_key";

export interface OCSPResponseCreateParams {
  /**
   * Response signature algorithm
   */
  signatureAlgorithm: AlgorithmIdentifier;
  /**
   * Response signing key
   */
  signingKey: CryptoKey;
  /**
   * The OCSP request for which the response is being generated
   */
  request: OCSPRequest;
  /**
   * The certificate that will be used to sign the response
   */
  responderCertificate: X509Certificate;
  /**
   * List of certificates that can be used to verify the signature of the response
   */
  certificates?: X509Certificate[];
  /**
   * The date and time for which the status of the certificate is issued
   * The default is the current time
   */
  date?: Date;
  /**
   * Certificate status
   * The default is successful
   */
  status?: OCSPResponseStatus;
  /**
   * List of response extensions
   */
  extensions?: Extension[];
}

export class OCSPResponseGenerator {
  /**
   * Creates an OCSP response and signs it.
   * @param params OCSP response creation options.
   * @param crypto Crypto provider. Default is from CryptoProvider.
   * @returns OCSP response.
   */
  public static async create(params: OCSPResponseCreateParams, crypto = cryptoProvider.get()): Promise<OCSPResponse> {
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);

    // Sign
    const tbs = AsnConvert.serialize(params.request);
    const signatureValue = await crypto.subtle.sign(params.signatureAlgorithm, params.signingKey, tbs);

    // Convert WebCrypto signature to ASN.1 format
    const signatureFormatters = container.resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter).reverse();
    let asnSignature: ArrayBuffer | null = null;
    for (const signatureFormatter of signatureFormatters) {
      asnSignature = signatureFormatter.toAsnSignature(params.signatureAlgorithm as HashedAlgorithm, signatureValue);
      if (asnSignature) {
        break;
      }
    }
    if (!asnSignature) {
      throw Error("Cannot convert ASN.1 signature value to WebCrypto format");
    }

    const responses: ocsp.SingleResponse[] = [];
    for (const req of params.request.requestList) {
      AsnConvert.parse(req.rawData, asn1X509.TBSCertList).thisUpdate;
      const resp = new ocsp.SingleResponse({
        certID: new ocsp.CertID({
          hashAlgorithm: algProv.toAsnAlgorithm(req.certificateID.hashAlgorithm),
          issuerNameHash: new OctetString(req.certificateID.issuerNameHash),
          issuerKeyHash: new OctetString(req.certificateID.issuerKeyHash),
          serialNumber: AsnConvert.serialize(req.certificateID.serialNumber)
        }),
        thisUpdate: AsnConvert.parse(req.rawData, asn1X509.TBSCertList).thisUpdate.getTime() || new Date(),
        nextUpdate: AsnConvert.parse(req.rawData, asn1X509.TBSCertList).nextUpdate?.getTime() || new Date(),
        singleExtensions: new asn1X509.Extensions(req.extensions.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension)) || [])
      });
      responses.push(resp);
    }

    const basicOCSPResp = new ocsp.BasicOCSPResponse({
      tbsResponseData: new ocsp.ResponseData({
        version: ocsp.Version.v1,
        responderID: new ocsp.ResponderID({ byKey: new OctetString(await params.responderCertificate.publicKey.getThumbprint("SHA-1", crypto)) }),
        producedAt: params.date || new Date(),
        responses,
        responseExtensions: new asn1X509.Extensions(params.extensions?.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension)) || [])
      }),
      signature: asnSignature,
      signatureAlgorithm: algProv.toAsnAlgorithm(params.signatureAlgorithm as HashedAlgorithm)
    });

    if (params.certificates) {
      for (const cert of params.certificates) {
        let spki: BufferSource;
        if (cert.publicKey instanceof PublicKey) {
          spki = cert.publicKey.rawData;
        } else if (BufferSourceConverter.isBufferSource(cert.publicKey)) {
          spki = cert.publicKey;
        } else {
          spki = await crypto.subtle.exportKey("spki", cert.publicKey);
        }

        const asnX509 = new asn1X509.Certificate({
          tbsCertificate: new asn1X509.TBSCertificate({
            version: asn1X509.Version.v3,
            serialNumber: Convert.FromHex(cert.serialNumber),
            signature: algProv.toAsnAlgorithm(params.signatureAlgorithm as HashedAlgorithm),
            validity: new asn1X509.Validity({
              notBefore: cert.notBefore,
              notAfter: cert.notAfter,
            }),
            subject: AsnConvert.parse(cert.subjectName.toArrayBuffer(), asn1X509.Name),
            issuer: AsnConvert.parse(cert.issuerName.toArrayBuffer(), asn1X509.Name),
            extensions: new asn1X509.Extensions(cert.extensions.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension)) || []),
            subjectPublicKeyInfo: AsnConvert.parse(spki, asn1X509.SubjectPublicKeyInfo),
          }),
          signatureAlgorithm: algProv.toAsnAlgorithm(params.signatureAlgorithm as HashedAlgorithm),
          signatureValue: signatureValue,
        });

        basicOCSPResp.certs?.push(asnX509);
      }
    }

    const asnOcspResponse = new ocsp.OCSPResponse({
      responseStatus: params.status || OCSPResponseStatus.successful,
      responseBytes: new ocsp.ResponseBytes({
        responseType: "",
        response: new OctetString(AsnConvert.serialize(basicOCSPResp))
      })
    });

    return new OCSPResponse(asnOcspResponse);
  }
}