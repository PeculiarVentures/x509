import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { isEqual } from "pvtsutils";
import { AuthorityKeyIdentifierExtension, SubjectKeyIdentifierExtension } from "./extensions";
import { X509Certificate } from "./x509_cert";
import { X509Certificates } from "./x509_certs";

export class X509ChainBuilder {

  public certificates: X509Certificate[] = [];

  public constructor(params: Partial<X509ChainBuilder> = {}) {
    if (params.certificates) {
      this.certificates = params.certificates;
    }
  }

  public async build(cert: X509Certificate) {
    const chain = new X509Certificates(cert);

    let current: X509Certificate | null = cert;
    // eslint-disable-next-line no-cond-assign
    while (current = await this.findIssuer(current)) {
      // check out circular dependency
      const thumbprint = await current.getThumbprint();
      for (const item of chain) {
        const thumbprint2 = await item.getThumbprint();
        if (isEqual(thumbprint, thumbprint2)) {
          throw new Error("Cannot build a certificate chain. Circular dependency.");
        }
      }

      chain.push(current);
    }

    return chain;
  }

  private async findIssuer(cert: X509Certificate) {
    if (!await cert.isSelfSigned()) {
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
          publicKey: await item.publicKey.export(),
          signatureOnly: true,
        })) {
          continue;
        }
        return item;
      }
    }
    return null;
  }

}