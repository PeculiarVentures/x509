import { AsnConvert } from "@peculiar/asn1-schema";
import * as asnX509 from "@peculiar/asn1-x509";
import * as asnPkcs9 from "@peculiar/asn1-pkcs9";
import { BufferSourceConverter } from "pvtsutils";
import { Attribute } from "../attribute";
import { Extension } from "../extension";
import { ExtensionFactory } from "../extensions";
import { TextObject } from "../text_converter";
import { ParseOptions } from "../types";
import { selfProducedParseOptions } from "../utils";

export class ExtensionsAttribute extends Attribute {
  public static override NAME = "Extensions";

  public items: Extension[];

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   * @param options Optional ASN.1 parse options (e.g. `asn1js.fromBER` resource limits)
   */
  public constructor(raw: BufferSource, options?: ParseOptions);
  /**
   * Creates a new instance
   * @param extensions
   */
  public constructor(extensions: Extension[]);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0] as BufferSource, args[1] as ParseOptions | undefined);
    } else {
      const extensions = args[0] as Extension[];
      const value = new asnX509.Extensions();
      for (const extension of extensions) {
        value.push(
          AsnConvert.parse(extension.rawData, asnX509.Extension, selfProducedParseOptions),
        );
      }
      super(asnPkcs9.id_pkcs9_at_extensionRequest, [AsnConvert.serialize(value)]);
    }

    this.items ??= [];
  }

  protected onInit(asn: asnX509.Attribute): void {
    super.onInit(asn);

    if (this.values[0]) {
      const value = AsnConvert.parse(this.values[0], asnX509.Extensions, this.parseOptions);
      this.items = value.map((o) =>
        ExtensionFactory.create(AsnConvert.serialize(o), this.parseOptions),
      );
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    const extensions = this.items.map((o) => o.toTextObject());
    for (const extension of extensions) {
      obj[extension[TextObject.NAME]] = extension;
    }

    return obj;
  }
}
