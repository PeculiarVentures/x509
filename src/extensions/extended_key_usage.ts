import * as asn1X509 from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { OidSerializer, TextObject } from "../text_converter";

export enum ExtendedKeyUsage {
  serverAuth = "1.3.6.1.5.5.7.3.1",
  clientAuth = "1.3.6.1.5.5.7.3.2",
  codeSigning = "1.3.6.1.5.5.7.3.3",
  emailProtection = "1.3.6.1.5.5.7.3.4",
  timeStamping = "1.3.6.1.5.5.7.3.8",
  ocspSigning = "1.3.6.1.5.5.7.3.9",
}

export type ExtendedKeyUsageType = asn1X509.ExtendedKeyUsage | string;


/**
 * Represents the Extended Key Usage certificate extension
 */
export class ExtendedKeyUsageExtension extends Extension {

  public static override NAME = "Extended Key Usages";
  /**
   * Gets a list of purposes for which the certified public key may be used
   */
  public readonly usages: ExtendedKeyUsageType[];

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
  public constructor(usages: ExtendedKeyUsageType[], critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);

      const value = AsnConvert.parse(this.value, asn1X509.ExtendedKeyUsage);
      this.usages = value.map(o => o);
    } else {
      const value = new asn1X509.ExtendedKeyUsage(args[0]);
      super(asn1X509.id_ce_extKeyUsage, args[1], AsnConvert.serialize(value));

      this.usages = args[0];
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    obj[""] = this.usages.map(o => OidSerializer.toString(o as string)).join(", ");

    return obj;
  }

}