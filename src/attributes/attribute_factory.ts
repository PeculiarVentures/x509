import { Attribute } from "../attribute";

/**
 * Static class to manage X509 attributes
 */
export class AttributeFactory {
  private static items = new Map<string, typeof Attribute>();

  /**
   * Registers a new X509 Attribute class. If id already exists replaces it
   * @param id Attribute identifier
   * @param type Attribute class
   *
   * @example
   * ```js
   * AttributeFactory.register(asnPkcs9.id_pkcs9_at_challengePassword, ChallengePasswordAttribute);
   * ```
   */
  public static register(id: string, type: any) {
    this.items.set(id, type);
  }

  /**
   * Returns X509 Attribute based on it's identifier
   * @param data DER encoded buffer
   *
   * @example
   * ```js
   * const attr = AttributeFactory.create(asnAttrRaw);
   * ```
   */
  public static create(data: BufferSource) {
    const attribute = new Attribute(data);
    const Type = this.items.get(attribute.type);
    if (Type) {
      return new Type(data);
    }

    return attribute;
  }
}
