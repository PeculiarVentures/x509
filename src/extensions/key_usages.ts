import { AsnConvert } from "@peculiar/asn1-schema";
import { id_ce_keyUsage, KeyUsage } from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { TextObject } from "../text_converter";

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
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param usages
   * @param critical
   */
  public constructor(usages: KeyUsageFlags, critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0] as BufferSource);

      const value = AsnConvert.parse(this.value, KeyUsage);
      this.usages = value.toNumber();
    } else {
      const value = new KeyUsage(args[0]);
      super(id_ce_keyUsage, args[1], AsnConvert.serialize(value));

      this.usages = args[0];
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    const asn = AsnConvert.parse(this.value, KeyUsage);

    obj[""] = asn.toJSON().join(", ");

    return obj;
  }
}
