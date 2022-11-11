import * as asn1X509 from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { isEqual } from "pvtsutils";
import { X509Certificate } from "./x509_cert";
import { X509Certificates } from "./x509_certs";
import { cryptoProvider } from "./provider";
import { AuthorityKeyIdentifierExtension, SubjectKeyIdentifierExtension } from "./extensions";

export interface IResult<T> {
  target: ICertificateStorageHandler;
  result: T;
  error?: Error;
}

export interface ICertificateStorageHandler {

  parent: ICertificateStorageHandler | null;

  certificates: X509Certificates;

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

export class DefaultCertificateStorageHandler implements ICertificateStorageHandler {

  public parent: ICertificateStorageHandler | null = null;
  public certificates = new X509Certificates();

  public async findIssuers(cert: X509Certificate, crypto = cryptoProvider.get()): Promise<X509Certificates> {
    const issuerCerts: X509Certificates = new X509Certificates();
    if (this.parent) {
      return await this.parent.findIssuers(cert, crypto);
    }

    // Self-signed certificate
    if (await cert.isSelfSigned(crypto)) {
      issuerCerts.push(cert);
    } else {
      const akiExt = cert.getExtension<AuthorityKeyIdentifierExtension>(asn1X509.id_ce_authorityKeyIdentifier);
      for (const item of this.certificates) {
        if (item.subject !== cert.issuer) {
          continue;
        }

        if (akiExt) {
          if (akiExt.keyId) {
            const skiExt = item.getExtension<SubjectKeyIdentifierExtension>(asn1X509.id_ce_subjectKeyIdentifier);
            if (skiExt && skiExt.keyId !== akiExt.keyId) {
              continue;
            }
          } else if (akiExt.certId) {
            const sanExt = item.getExtension<SubjectKeyIdentifierExtension>(asn1X509.id_ce_subjectAltName);
            if (sanExt &&
              !(akiExt.certId.serialNumber === item.serialNumber && isEqual(AsnConvert.serialize(akiExt.certId.name), AsnConvert.serialize(sanExt)))) {
              continue;
            }
          }
        }
        if (!await cert.verify({
          publicKey: await item.publicKey.export(crypto),
          signatureOnly: true,
        }, crypto)) {
          continue;
        }

        issuerCerts.push(item);
      }
    }

    return issuerCerts;
  }

  public async isTrusted(cert: X509Certificate): Promise<IResult<boolean>> {
    if (this.parent) {
      const trusted = await this.parent.isTrusted(cert);
      if (trusted) {
        return trusted;
      }
    }

    return {
      target: this,
      result: false,
    };
  }
}