import { ChainRuleValidateParams, ChainRuleValidateResult } from "../x509_chain_validator";
import { ChainRule, ChainRuleType } from "./rule_registry";
import {X509CertificateTree}  from "../x509_certificate_tree";
import { OCSPWorker } from "../ocsp";


/**
 * Revoked Rule
 * This rule checks the if the certificate is revoked by the issuer
 */
export class RevokedRule implements ChainRule {

  public id = "revoked";
  public type = ChainRuleType.critical;

  public async validate(params: ChainRuleValidateParams): Promise<ChainRuleValidateResult> {
    const certificate = params.cert;
    const X509Chain = new X509CertificateTree();
    const node = params.node;
    // check if the certificate is self-signed
    // if it is self-signed, no further checks are made, assuming that the certificate is trusted
    if(await certificate.isSelfSigned()){
      const result = { code: this.id, type: this.type,  status: true, details: "The certificate is self-signed" }
      X509Chain.appendNodeData(node, certificate.serialNumber, result);

      return result;
    }else{
      let issuer;
      // find certificate in a list with a subject field equal to the issuer field of the certificate being checked
      for (const cert of params.chain) {
        if (cert.subject == certificate.issuer) {
          issuer = cert;
        }
      }
      if (!issuer) throw new Error("Issuer not found");

      //get OCSP response on the certificate
      const ocspWorker = await OCSPWorker.create(certificate, issuer);
      const status = await ocspWorker.sendRequest();

      if (status !== true){
        const result = { code: this.id, type: this.type, status: false, details: "OCSP response is malformed" };
        X509Chain.appendNodeData(node, certificate.serialNumber, result);

        return result;
      }else{

        // try to find the OCSP certificate in the Tree
        // if the certificate is found check it's revocation status
        // TODO: if it's revocation status has not been checked, verify it with OCSP
        // Currently, it will return failure on unverified revocation status
        if (ocspWorker.response.basicResponse?.responderID){

          const responderID = ocspWorker.response.basicResponse.responderID;
          const responderCert = X509Chain.findCertificateByResponderID(responderID, node);
          // if responderCert is found check if it has not been revoked
          if(responderCert !== undefined){
            const responderRulesResults = X509Chain.getRulesData(node, responderCert.serialNumber);
            // if the certificate is not revoked return the success message
            if(responderRulesResults.length > 0){
              // find Rule result with the id "revoked"
              const revokedResult = responderRulesResults.find(result => result.code === "revoked");
              if(revokedResult){
                if(revokedResult.status === true){
                  const result = { code: this.id, type: this.type, status: true, details: "The certificate is not revoked" };
                  X509Chain.appendNodeData(node, certificate.serialNumber, result);

                  return result;
                }else{
                  const result = { code: this.id, type: this.type, status: false, details: "The OCSP provider certificate is revoked" };
                  X509Chain.appendNodeData(node, certificate.serialNumber, result);

                  return result;
                }
              }
            }
          }
        }
        //TODO if the certificate is not found in the tree, get the certificate from the OCSP provider
        const result = { code: this.id, type: this.type, status: false, details: "failed to verify OCSP Server" };
        X509Chain.appendNodeData(node, certificate.serialNumber, result);

        return result;
      }
    }
    const result = { code: this.id, type: this.type, status: false, details: "The certificate is revoked" };
    X509Chain.appendNodeData(node, certificate.serialNumber, result);

    return result;
  }
}

