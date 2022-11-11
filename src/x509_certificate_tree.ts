import { ICertificateStorage, ICertificateStorageHandler, IResult } from "./certificate_storage_handler";
import { DefaultCertificateStorageHandler } from "./certificate_storage_handler";
import { cryptoProvider } from "./provider";
import { X509Certificate } from "./x509_cert";
import { X509Certificates } from "./x509_certs";
import { Convert } from "pvtsutils";

type IX509CertificateNodeState = "valid" | "invalid" | "unknown";

export interface IX509CertificateNode {
  certificate: X509Certificate;
  nodes: IX509CertificateNode[];
  state: IX509CertificateNodeState;
}

export class X509CertificateTree implements ICertificateStorage {
  public certificateStorage: ICertificateStorageHandler = new DefaultCertificateStorageHandler();
  public certificatesTree: IX509CertificateNode | null = null;

  //deep walk through the object tree
  public treeBranchFilling(certificatesTree: IX509CertificateNode, lastCert: X509Certificate, parentCert: X509Certificate): IX509CertificateNode {
    if (certificatesTree.certificate.equal(lastCert)) {
      if (certificatesTree.nodes.length) {
        if (!certificatesTree.nodes.some(item => { item.certificate.equal(parentCert); })) {
          certificatesTree.nodes.push({ certificate: parentCert, nodes: [], state: 'unknown' });
        }
      } else {
        certificatesTree.nodes.push({ certificate: parentCert, nodes: [], state: 'unknown' });
      }
    } else {
      certificatesTree.nodes.forEach(item => {
        this.treeBranchFilling(item, lastCert, parentCert);
      });
    }
    return certificatesTree;
  }

  public async buildTree(cert: X509Certificate, crypto = cryptoProvider.get()): Promise<IX509CertificateNode> {
    let lastCert: X509Certificate | null = cert;
    let lastCerts: X509Certificates | null;
    const certificateInfo: IX509CertificateNode = { certificate: lastCert, nodes: [], state: "unknown" };

    if (!this.certificatesTree) {
      this.certificatesTree = certificateInfo;
    }

    if (lastCert.subject === lastCert.issuer) {
      return this.certificatesTree;
    }

    lastCerts = await this.certificateStorage.findIssuers(lastCert, crypto);

    if (lastCerts) {
      for (var i = 0; i < lastCerts.length; i++) {
        this.certificatesTree = this.treeBranchFilling(this.certificatesTree, lastCert, lastCerts[i]);

        await this.buildTree(lastCerts[i], crypto);
      }
    }
    return this.certificatesTree;
  }
}