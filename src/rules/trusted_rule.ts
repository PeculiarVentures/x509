import { ChainRule, ChainRuleType } from "./rule_registry";
import { X509CertificateTree } from "../x509_certificate_tree";
import { ChainRuleValidateParams, ChainRuleValidateResult } from "../x509_chain_validator";

/**
 * Trusted Rule
 * This rule checks that parent certificates are included in the list of trusted certificates
 */
export class TrustedRule implements ChainRule {

  public id = "trusted";
  public type: ChainRuleType = "critical";

  public async validate(params: ChainRuleValidateParams): Promise<ChainRuleValidateResult> {
    const chain = new X509CertificateTree();
    chain.certificateStorage.certificates = params.chain;
    const trustedChain = await chain.certificateStorage.isTrusted(params.cert);
    if (!trustedChain.result) {
      return { code: this.id, status: false, details: "Parent certificates are not included in trusted list" };
    } else {
      return { code: this.id, status: true, details: "Parent certificates are included in trusted list" };
    }
  }
}