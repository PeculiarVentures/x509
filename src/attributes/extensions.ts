import { AsnConvert } from "@peculiar/asn1-schema";
import * as asnX509 from "@peculiar/asn1-x509";
import * as asnPkcs9 from "@peculiar/asn1-pkcs9";
import { BufferSourceConverter } from "pvtsutils";
import { Attribute } from "../attribute";
import { Extension } from "../extension";
import { ExtensionFactory } from "../extensions";

export class ExtensionsAttribute extends Attribute {

  public items: Extension[];

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param extensions
   */
  public constructor(extensions: Extension[]);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);
    } else {
      const value = new asnX509.Extensions(args[0]);
      super(asnPkcs9.id_pkcs9_at_extensionRequest, [AsnConvert.serialize(value)]);
    }

    this.items ??= [];
  }

  protected onInit(asn: asnX509.Attribute): void {
    super.onInit(asn);

    if (this.values[0]) {
      const value = AsnConvert.parse(this.values[0], asnX509.Extensions);
      this.items = value.map(o => ExtensionFactory.create(AsnConvert.serialize(o)));
    }

  }

}