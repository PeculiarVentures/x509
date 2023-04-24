import { ChainRuleValidateParams, ChainRuleValidateResult } from "../x509_chain_validator";
import { ChainRule, ChainRuleType } from "./rule_registry";

/**
 * Expired Rule
 * This rule checks the validity period of certificates in the certificate chain
 */
export class ExpiredRule implements ChainRule {

  public id = "expired";
  public type: ChainRuleType = "critical";
  public checkDate: Date = new Date();

  public async validate(params: ChainRuleValidateParams): Promise<ChainRuleValidateResult> {
    if (params.cert.notAfter.getTime() < this.checkDate.getTime()) {
      return { code: this.id, status: false, details: "The certificate is expired" };
    } else if (params.cert.notBefore.getTime() > this.checkDate.getTime()) {
      return { code: this.id, status: false, details: "The certificate is not yet valid" };
    } else {
      return { code: this.id, status: true, details: "The certificate is valid" };
    }
  }
}