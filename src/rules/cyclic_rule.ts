import { isEqual } from "pvtsutils";
import { cryptoProvider } from "../provider";
import { ChainRule, ChainRuleType } from "./rule_registry";
import { ChainRuleValidateParams, ChainRuleValidateResult } from "../x509_chain_validator";

/**
 * Cyclic Rule
 * This rule checks the chain of certificates for cyclicity
 */
export class CyclicRule implements ChainRule {

  public id = "cyclic";
  public type: ChainRuleType = "critical";

  public async validate(params: ChainRuleValidateParams): Promise<ChainRuleValidateResult> {
    const crypto = cryptoProvider.get();
    for (let i = 0; i < params.chain.length; i++) {
      const thumbprint = await params.chain[i].getThumbprint(crypto);
      for (let j = i + 1; j < params.chain.length; j++) {
        const thumbprint2 = await params.chain[j].getThumbprint(crypto);
        if (isEqual(thumbprint, thumbprint2)) {
          return { code: this.id, status: false, details: "Circular dependency." };
        }
      }
    }

    return { code: this.id, status: true, details: "The certificate chain is valid" };
  }
}