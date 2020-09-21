import { CertificationRequest, CertificationRequestInfo } from "@peculiar/asn1-csr";
import { id_pkcs9_at_extensionRequest } from "@peculiar/asn1-pkcs9";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Name as AsnName, Extension as AsnExtension, SubjectPublicKeyInfo, Extensions, Attribute  as AsnAttribute } from "@peculiar/asn1-x509";
import { container } from "tsyringe";
import { cryptoProvider } from "./provider";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { Attribute } from "./attribute";
import { Extension } from "./extension";
import { JsonName, Name } from "./name";
import { Pkcs10CertificateRequest } from "./pkcs10_cert_req";
import { HashedAlgorithm } from "./types";

export type Pkcs10CertificateRequestCreateParamsName = string | JsonName;

/**
 * Pkcs10CertificateRequest create parameters
 */
export interface Pkcs10CertificateRequestCreateParams {
  /**
   * Subject name
   */
  name: Pkcs10CertificateRequestCreateParamsName;
  /**
   * Extensions
   */
  extensions?: Extension[];
  /**
   * Attributes
   */
  attributes?: Attribute[];
  /**
   * Signing algorithm
   */
  signingAlgorithm: Algorithm | EcdsaParams;
  /**
   * Crypto key pair
   */
  keys: CryptoKeyPair;
}

/**
 * Generator of PKCS10 certificate requests
 */
export class Pkcs10CertificateRequestGenerator {

  /**
   * Creates a new PKCS10 Certificate request
   * @param params Create parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async create(params: Pkcs10CertificateRequestCreateParams, crypto = cryptoProvider.get()) {
    const spki = await crypto.subtle.exportKey("spki", params.keys.publicKey);
    const asnReq = new CertificationRequest({
      certificationRequestInfo: new CertificationRequestInfo({
        subject: AsnConvert.parse(new Name(params.name).toArrayBuffer(), AsnName),
        subjectPKInfo: AsnConvert.parse(spki, SubjectPublicKeyInfo),
      }),
    });

    if (params.attributes) {
      // Add attributes
      for (const o of params.attributes) {
        asnReq.certificationRequestInfo.attributes.push(AsnConvert.parse(o.rawData, AsnAttribute));
      }
    }

    if (params.extensions && params.extensions.length) {
      // Add extensions
      const attr = new AsnAttribute({ type: id_pkcs9_at_extensionRequest})
      const extensions = new Extensions();
      for (const o of params.extensions) {
        extensions.push(AsnConvert.parse(o.rawData, AsnExtension));
      }
      attr.values.push(AsnConvert.serialize(extensions));
      asnReq.certificationRequestInfo.attributes.push(attr);
    }

    // Set signing algorithm
    const signingAlgorithm = { ...params.signingAlgorithm, ...params.keys.privateKey.algorithm } as HashedAlgorithm;
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    asnReq.signatureAlgorithm = algProv.toAsnAlgorithm(signingAlgorithm);

    // Sign
    const tbs = AsnConvert.serialize(asnReq.certificationRequestInfo);
    const signature = await crypto.subtle.sign(signingAlgorithm, params.keys.privateKey, tbs);
    asnReq.signature = signature;

    return new Pkcs10CertificateRequest(AsnConvert.serialize(asnReq));
  }

}