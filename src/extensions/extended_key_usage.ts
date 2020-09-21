import { ExtendedKeyUsage, id_ce_extKeyUsage } from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";

/**
 * Represents the Extended Key Usage certificate extension
 */
export class ExtendedKeyUsageExtension extends Extension {

  /**
   * Gets a list of purposes for which the certified public key may be used
   */
  public readonly usages: string[];

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param usages
   * @param critical
   */
  public constructor(usages: string[], critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);

      const value = AsnConvert.parse(this.value, ExtendedKeyUsage);
      this.usages = value.map(o => o);
    } else {
      const value = new ExtendedKeyUsage(args[0]);
      super(id_ce_extKeyUsage, args[1], AsnConvert.serialize(value));

      this.usages = args[0];
    }
  }
}
