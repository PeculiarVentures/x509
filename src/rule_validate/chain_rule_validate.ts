import { isEqual } from "pvtsutils";
import { DefaultCertificateStorageHandler } from "../certificate_storage_handler";
import { X509Certificate } from "../x509_cert";
import { IX509CertificateNode } from "../x509_certificate_tree";
import { X509Certificates } from "../x509_certs";
import { cryptoProvider } from "../provider";
import { ChainValidatorItem } from "./chain_validate";

export interface ChainRuleValidateParams {
  node: IX509CertificateNode;
  cert: X509Certificate;
  chain: X509Certificates;
  options: any;
  checkDate: Date;
}

export interface ChainRuleValidateResult {
  status: boolean;
  details: string;
}

class Rules {

  public async cyclicValidate(params: ChainRuleValidateParams, crypto = cryptoProvider.get()): Promise<ChainRuleValidateResult> {
    for (const chainCert of params.chain) {
      const thumbprint = await chainCert.getThumbprint(crypto);
      for (const cert of params.chain) {
        const thumbprint2 = await cert.getThumbprint(crypto);
        if (isEqual(thumbprint, thumbprint2)) {
          return { status: false, details: "Circular dependency." };
        }
      }
    }

    return { status: true, details: "The certificate chain is valid" };
  }

  public verifiedCertificates: ChainValidatorItem[] = [];

  public recordingCertificateVerificationResults(chainCert: X509Certificate, result: ChainRuleValidateResult) {
    const desiredCertificate = this.verifiedCertificates.find(async (certInfo) => {
      const thumbprint = await certInfo.certificate.getThumbprint(crypto);
      const thumbprint2 = await chainCert.getThumbprint(crypto);
      isEqual(thumbprint, thumbprint2);
    });
    if (!!desiredCertificate) {
      desiredCertificate.results.push(result);
    } else {
      this.verifiedCertificates.push({ certificate: chainCert, results: [result], status: true });
    }
  }

  public async expiredValidate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]> {
    for (const chainCert of params.chain) {
      if (chainCert.notAfter.getTime() < params.checkDate.getTime()) {
        this.recordingCertificateVerificationResults(chainCert, { status: false, details: "The certificate is expired" });
      }
      if (chainCert.notBefore.getTime() > params.checkDate.getTime()) {
        this.recordingCertificateVerificationResults(chainCert, { status: false, details: "The certificate is not valid" });
      }
    }

    return this.verifiedCertificates;
  }

  public async trustedValidate(params: ChainRuleValidateParams): Promise<ChainValidatorItem[]> {
    for (const chainCert of params.chain) {
      const trustedChain = await (params.chain as unknown as DefaultCertificateStorageHandler).isTrusted(chainCert);
      if (!trustedChain.result) {
        this.recordingCertificateVerificationResults(chainCert, { status: false, details: "Parent certificates are not included in trusted list" });
      } else {
        this.recordingCertificateVerificationResults(chainCert, { status: true, details: "Parent certificates are included in trusted list" });
      }
    }

    return this.verifiedCertificates;
  }

}