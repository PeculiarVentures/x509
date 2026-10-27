import * as asn1X509 from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { isBufferSource } from "@peculiar/utils";
import { Extension } from "../extension";
import type { TextObject } from "../text_converter";
import { OidSerializer } from "../text_converter";
import type { ParseOptions } from "../types";

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
   * @param options Optional ASN.1 parse options (e.g. `asn1js.fromBER` resource limits)
   */
  public constructor(raw: BufferSource, options?: ParseOptions);
  /**
   * Creates a new instance
   * @param usages
   * @param critical
   */
  public constructor(usages: ExtendedKeyUsageType[], critical?: boolean);
  public constructor(...args: any[]) {
    if (isBufferSource(args[0])) {
      super(args[0] as BufferSource, args[1] as ParseOptions | undefined);

      const value = AsnConvert.parse(this.value, asn1X509.ExtendedKeyUsage, this.parseOptions);
      this.usages = value.map((o) => o);
    } else {
      const value = new asn1X509.ExtendedKeyUsage(args[0]);
      super(asn1X509.id_ce_extKeyUsage, args[1], AsnConvert.serialize(value));

      this.usages = args[0];
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    obj[""] = this.usages.map((o) => OidSerializer.toString(o as string)).join(", ");

    return obj;
  }
}
