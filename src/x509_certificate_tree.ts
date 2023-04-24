import { ICertificateStorage, ICertificateStorageHandler } from "./certificate_storage_handler";
import { DefaultCertificateStorageHandler } from "./default_certificate_storage_handler";
import { cryptoProvider } from "./provider";
import { X509Certificate } from "./x509_cert";
import { Convert } from "pvtsutils";

type IX509CertificateNodeState = "valid" | "invalid" | "unknown";

export interface IX509CertificateNode {
  certificate: X509Certificate;
  nodes: IX509CertificateNode[];
  state: IX509CertificateNodeState;
}

type CertificateThumbprint = string;

type X509ChainNodeStorage = Record<CertificateThumbprint, IX509CertificateNode>;

export class X509CertificateTree implements ICertificateStorage {
  public certificateStorage: ICertificateStorageHandler = new DefaultCertificateStorageHandler();
  public chainNodeStorage: X509ChainNodeStorage = {};
  public cyclicality = false;

  /**
   * Returns the node of the certificate
   */
  public createNode(cert: X509Certificate): IX509CertificateNode {
    return { certificate: cert, nodes: [], state: "unknown" };
  }

  /**
   * Returns a filled node
   * @param certificatesTree Certificates tree
   * @param lastCert Issued certificate
   * @param parentCert Issuer certificates
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns certificates tree
   */
  public async fillNode(certificatesTree: IX509CertificateNode, lastCert: X509Certificate, parentCert: X509Certificate, crypto = cryptoProvider.get()) {
    const thumbprint2 = Convert.ToHex(await parentCert.getThumbprint(crypto));
    if (certificatesTree.certificate.equal(lastCert)) {
      if (this.chainNodeStorage && !(thumbprint2 in this.chainNodeStorage)) {
        certificatesTree.nodes.push(this.createNode(parentCert));
      } else {
        if (!certificatesTree.nodes.some(item => item.certificate.equal(parentCert))) {
          certificatesTree.nodes.push(this.createNode(parentCert));
        } else {
          this.cyclicality = true;
        }
      }
    } else {
      certificatesTree.nodes.forEach(async (item) => {
        await this.fillNode(item, lastCert, parentCert);
      });
    }
  }


  /**
   * Returns part of the constructed certificate tree
   * @param cert Issued certificate
   * @param crypto Crypto provider. Default is from CryptoProvider
   * @returns certificates tree
   */
  async #build(cert: X509Certificate, certificatesTree: IX509CertificateNode, crypto = cryptoProvider.get()): Promise<IX509CertificateNode> {
    const thumbprint = Convert.ToHex(await cert.getThumbprint(crypto));
    if (this.chainNodeStorage && !(thumbprint in this.chainNodeStorage) || !this.chainNodeStorage) {
      this.chainNodeStorage = { [thumbprint]: this.createNode(cert), ...this.chainNodeStorage };
    }

    if (await cert.isSelfSigned(crypto)) {
      this.cyclicality = false;

      return certificatesTree;
    }

    const lastCerts = await this.certificateStorage.findIssuers(cert, crypto);

    if (lastCerts) {
      for (let i = 0; i < lastCerts.length; i++) {
        await this.fillNode(certificatesTree, cert, lastCerts[i]);
        if (!this.chainNodeStorage[thumbprint].nodes.some(item => lastCerts && item.certificate.equal(lastCerts[i]))) {
          this.chainNodeStorage[thumbprint].nodes.push(this.createNode(lastCerts[i]));
        }
        if (this.cyclicality) {
          this.cyclicality = false;

          continue;
        }
        await this.#build(lastCerts[i], certificatesTree);
      }
    }

    return certificatesTree;
  }

  public async build(cert: X509Certificate): Promise<IX509CertificateNode> {
    return await this.#build(cert, this.createNode(cert));
  }
}