import { Extension } from "../extension";
import { GeneralName } from "../general_name";
import { X509Certificate } from "../x509_cert";
import { OCSPRequest } from "./ocsp_request";

export interface OCSPRequestCreateParams {
  /**
   * The name of the requestor
   */
  requestorName?: GeneralName;
  /**
   * The certificate for which the status is being requested
  */
  certificate: X509Certificate;
  /**
   * The certificate of the certificate issuer for which the status is being requested
   */
  issuer: X509Certificate;
  /**
   * Gets a list of request extensions
   */
  extensions?: Extension[];
  /**
   * The hashing algorithm identifier for signing the OCSP request
   * If not specified, no signature is required
   */
  signatureAlgorithm?: AlgorithmIdentifier;
  /**
   * OCSP request signing key
   * If not specified, no signature is required
   */
  signingKey?: CryptoKey;
}

export class OCSPRequestGenerator {
  /**
   * Generates an OCSP request
   * @param params OCSP Request Generation Options
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns OCSP request
   */
  public static create(params: OCSPRequestCreateParams, crypto?: Crypto): Promise<OCSPRequest>;
}