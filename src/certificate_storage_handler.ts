import { X509Certificate } from "./x509_cert";
import { X509Certificates } from "./x509_certs";
import { X509Crl } from "./x509_crl";

export interface IResult<T> {
  target: ICertificateStorageHandler;
  result: T;
  error?: Error;
}

export type RevocationType = "crl" | "ocsp";

export interface ICertificateStorageHandler {

  parent: ICertificateStorageHandler | null;

  certificates: X509Certificates;
  crls?: X509Crl[];

  /**
   * Returns issuer certificate or certificates
   * @param cert Issued certificate
   * @returns Issuer certificates
   */
  findIssuers(cert: X509Certificate, crypto?: Crypto): Promise<X509Certificates>;

  /**
   * Returns true if certificate is trusted
   */
  isTrusted(cert: X509Certificate): Promise<IResult<boolean>>;

}

export interface ICertificateStorage {
  certificateStorage: ICertificateStorageHandler;
}