import { AsnConvert } from "@peculiar/asn1-schema";
import { id_ce_keyUsage, KeyUsage } from "@peculiar/asn1-x509";
import { isBufferSource } from "@peculiar/utils";
import { Extension } from "../extension";
import type { TextObject } from "../text_converter";
import type { ParseOptions } from "../types";

/**
 * X509 key usages flags
 */
export enum KeyUsageFlags {
  digitalSignature = 1,
  nonRepudiation = 2,
  keyEncipherment = 4,
  dataEncipherment = 8,
  keyAgreement = 16,
  keyCertSign = 32,
  cRLSign = 64,
  encipherOnly = 128,
  decipherOnly = 256,
}

/**
 * Represents the Key Usage certificate extension
 */
export class KeyUsagesExtension extends Extension {
  public static override NAME = "Key Usages";

  /**
   * Gets a key usages flag
   */
  public readonly usages: KeyUsageFlags;

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   * @param options Optional ASN.1 parse options (e.g. `asn1js.fromBER` resource limits)
   */
  public constructor(raw: BufferSource, options?: ParseOptions);
  /**
   * Creates a new instance
   * @param usages
   * @param critical
   */
  public constructor(usages: KeyUsageFlags, critical?: boolean);
  public constructor(...args: any[]) {
    if (isBufferSource(args[0])) {
      super(args[0] as BufferSource, args[1] as ParseOptions | undefined);

      const value = AsnConvert.parse(this.value, KeyUsage, this.parseOptions);
      this.usages = value.toNumber();
    } else {
      const value = new KeyUsage(args[0]);
      super(id_ce_keyUsage, args[1], AsnConvert.serialize(value));

      this.usages = args[0];
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    const asn = AsnConvert.parse(this.value, KeyUsage, this.parseOptions);

    obj[""] = asn.toJSON().join(", ");

    return obj;
  }
}
