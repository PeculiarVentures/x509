import { Extension } from "../extension";
import type { ParseOptions } from "../types";

/**
 * Static class to manage X509 extensions
 */
export class ExtensionFactory {
  private static items = new Map<string, typeof Extension>();

  /**
   * Registers a new X509 Extension class. If id already exists replaces it
   * @param id Extension identifier
   * @param type Extension class
   *
   * @example
   * ```js
   * ExtensionFactory.register(
   *   asnX509.id_ce_basicConstraints,
   *   extensions.BasicConstraintsExtension,
   * );
   * ```
   */
  public static register(id: string, type: any) {
    this.items.set(id, type);
  }

  /**
   * Returns X509 Extension based on it's identifier
   * @param data DER encoded buffer
   * @param options Optional ASN.1 parse options (e.g. `asn1js.fromBER` resource limits)
   *
   * @example
   * ```js
   * const ext = ExtensionFactory.create(asnExtRaw);
   * ```
   */
  public static create(data: BufferSource, options?: ParseOptions) {
    const extension = new Extension(data, options);
    const Type = this.items.get(extension.type);
    if (Type) {
      return new Type(data, options);
    }

    return extension;
  }
}
