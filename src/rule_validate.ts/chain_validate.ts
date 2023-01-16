import { X509Certificate } from "../x509_cert";
import { ChainRuleValidateResult } from "./chain_rule_validate";

export interface ChainValidatorResult {
  status: boolean;
  items: ChainValidatorItem[];
}

export interface ChainValidatorItem {
  certificate: X509Certificate;
  results: ChainRuleValidateResult[]; // Record<id, ChainRuleValidateResult> ; all rules
  status: boolean;
}

export interface ChainValidator {

  /**
     * Determines the validity of the chain
     * @param options Chain validator elements array
     * @returns Chain Validator Result
     */
  validate(options: ChainValidatorItem[]): Promise<ChainValidatorResult>;
}

export class ChainValidate implements ChainValidator {

  public async validate(options: ChainValidatorItem[]): Promise<ChainValidatorResult> {
    for (const item of options) {
      if (!item.status) {
        return { status: false, items: options };
      }
    }
    return { status: true, items: options };
  }

}