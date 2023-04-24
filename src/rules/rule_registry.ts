import { ChainRuleValidateParams, ChainRuleValidateResult } from "../x509_chain_validator";

export type ChainRuleType =
  "critical" | //critical - ошибка, которая приводит к прерыванию проверки и установке статуса "invalid"
  "error" |    //error - ошибка, которая не приводит к прерыванию проверки и установке статуса "invalid"
  "notice" |   //warning - предупреждение, которое не приводит к прерыванию проверки и не меняет статус
  "warning";   //notice - информационное сообщение, которое не приводит к прерыванию проверки и не меняет статус

export interface ChainRule {
  id: string;
  type: ChainRuleType;
  validate(params: ChainRuleValidateParams): Promise<ChainRuleValidateResult>;
}

export interface RuleValidatorResult {
  status: boolean;
  items: ChainRuleValidateResult[];
}

export class RuleRegistry {
  items: ChainRule[] = [];

  /**
   * Добавление правила валидации
   * @param rule правило валидации
   */
  add(rule: ChainRule): void {
    this.items.push(rule);
  }

  /**
   * Returns a rule of the specified type
   * @param type Rule
   * @returns Rule
   */
  get<T extends ChainRule>(type: new () => T): T {
    return this.items.find(rule => {
      return rule instanceof type;
    }) as T;
  }

  /**
   * Removes all items from rules
   */
  clear(): void {
    while (this.items.pop()) {
      //nothing
    }
  }
}

export class Rules {
  public registry: RuleRegistry = new RuleRegistry();

  constructor(registry: RuleRegistry) {
    this.registry = registry;
  }
  async validates(params: ChainRuleValidateParams): Promise<RuleValidatorResult> {
    const result: RuleValidatorResult = { items: [], status: true };

    for (let i = 0; i < this.registry.items.length; i++) {
      const item = await this.registry.items[i].validate(params);
      result.items.push(item);
      if (item.status === false) {
        result.status = false;

        // если проверка имеет тип "critical", то дальнейшая проверка не имеет смысла
        if (this.registry.items[i].type === "critical") {
          break;
        }
      }
    }

    return result;
  }
}