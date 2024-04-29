import * as ocsp from "@peculiar/asn1-ocsp";
import * as asn1X509 from "@peculiar/asn1-x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { container } from "tsyringe";
import { Convert } from "pvtsutils";
import { Extension } from "../extension";
import { cryptoProvider } from "../provider";
import { X509Certificate } from "../x509_cert";
import { OCSPResponse, OCSPResponseStatus } from "./ocsp_response";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";

export interface SingleResponseInterface {
  /**
   * certificate to which the response applies
   */
  certificate: X509Certificate;
  /**
   * issuer of the certificate to which the response applies
   */
  issuer: X509Certificate;
  /**
   * certificate status
   */
  status: OCSPResponseStatus;
  /**
   * Time the status of the certificate was last updated
   */
  thisUpdate: Date;
  /**
   * Time the status of the certificate will be next updated.
   * OPTIONAL, if nextUpdate is not set, the responder is indicating that newer
   * revocation information is available all the time.
   */
  nextUpdate?: Date;
  /**
   * List of single response extensions
   */
  extensions: Extension[];

}
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
   * the Single Response data for which the response is being generated
   */
  singleResponses: SingleResponseInterface[];
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

    // assemble single responses
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    const paramsSignatureAlgorithm = params.signatureAlgorithm;
    // if signature algorithm is undefined use sha-1
    // else convert it using algorithm provider
    let hashAlgorithm: asn1X509.AlgorithmIdentifier;
    let signatureAlgorithm: Algorithm;
    if(!paramsSignatureAlgorithm) {
      signatureAlgorithm = {name: "SHA-1"};
      hashAlgorithm = algProv.toAsnAlgorithm({ name: "SHA-1"});
    }else if(typeof paramsSignatureAlgorithm === "string"){
      hashAlgorithm = algProv.toAsnAlgorithm({ name: paramsSignatureAlgorithm});
      signatureAlgorithm = {name: paramsSignatureAlgorithm};
    }else{
      hashAlgorithm = algProv.toAsnAlgorithm(paramsSignatureAlgorithm);
      signatureAlgorithm = params.signatureAlgorithm as Algorithm;
    }

    //TODO add support for other algorithms
    const signingAlgorithm = {name : "ECDSA",
                              hash: signatureAlgorithm,
                              namedCurve: "P-256"};

    const responses: ocsp.SingleResponse[] = [];
    for(const singleResponse of params.singleResponses) {
      const response = new ocsp.SingleResponse({
        certID: new ocsp.CertID({
          // if hash algorithm is undefined use sha-1
          hashAlgorithm: hashAlgorithm,
          issuerNameHash: new OctetString(await singleResponse.issuer.subjectName.getThumbprint(crypto)),
          issuerKeyHash: new OctetString(await singleResponse.issuer.publicKey.getKeyIdentifier(crypto)),
          serialNumber: Convert.FromHex(singleResponse.certificate.serialNumber)
        }),
        certStatus: new ocsp.CertStatus({good: null}),
        thisUpdate: singleResponse.thisUpdate,
        // nextUpdate is optional
        ...(singleResponse.nextUpdate ? { nextUpdate: singleResponse.nextUpdate } : {})
      });
      responses.push(response);
    }

    // construct tbsResponseData and get signature using signing key
    const tbsResponseData = new ocsp.ResponseData({
      version: ocsp.Version.v1,
      responderID: new ocsp.ResponderID({ byKey: new OctetString(await params.responderCertificate.publicKey.getThumbprint("SHA-1", crypto)) }),
      producedAt: params.date || new Date(),
      responses,
      responseExtensions: new asn1X509.Extensions(params.extensions?.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension)) || [])
    });

    const tbs = AsnConvert.serialize(tbsResponseData);
    const signatureValue = await crypto.subtle.sign(signingAlgorithm, params.signingKey, tbs);

    // const signatureAlgorithm2 = {...paramsSignatureAlgorithm, ...params.signingKey.algorithm} as HashedAlgorithm;
    const basicOCSPResp = new ocsp.BasicOCSPResponse({
      tbsResponseData: tbsResponseData,
      signature: signatureValue,
      signatureAlgorithm: algProv.toAsnAlgorithm(signingAlgorithm)
    });

    // append cert to the response
    if(params.certificates) {
      basicOCSPResp.certs = [];
      for(const certificate of params.certificates){
        const ans1Cert = AsnConvert.parse(certificate.rawData, asn1X509.Certificate);
        basicOCSPResp.certs.push(ans1Cert);
      }
    }

    const asnOcspResponse = new ocsp.OCSPResponse({
      responseStatus: params.status || OCSPResponseStatus.successful,
      responseBytes: new ocsp.ResponseBytes({
        responseType: "1.3.6.1.5.5.7.48.1.1",
        response: new OctetString(AsnConvert.serialize(basicOCSPResp))
      })
    });

    return new OCSPResponse(asnOcspResponse);
  }
}