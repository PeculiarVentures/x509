import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { Extension as AsnExtension } from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { AsnData } from "./asn_data";
import { OidSerializer, TextObject } from "./text_converter";
import { ParseOptions } from "./types";
import { selfProducedParseOptions } from "./utils";

/**
 * Represents the certificate extension
 */
export class Extension extends AsnData<AsnExtension> {
  /**
   * Gets an extension identifier
   */
  public type!: string;
  /**
   * Indicates where extension is critical
   */
  public critical!: boolean;

  /**
   * Gets a DER encoded value of extension
   */
  public value!: ArrayBuffer;

  /**
   * Creates a new instance from DER encoded Buffer
   * @param raw DER encoded buffer
   * @param options Optional ASN.1 parse options (e.g. `asn1js.fromBER` resource limits)
   */
  public constructor(raw: BufferSource, options?: ParseOptions);
  /**
   * Creates a new instance
   * @param type Extension identifier
   * @param critical Indicates where extension is critical
   * @param value DER encoded value of extension
   */
  public constructor(type: string, critical: boolean, value: BufferSource);
  public constructor(...args: any[]) {
    let raw: ArrayBuffer;
    let options: ParseOptions | undefined;
    if (BufferSourceConverter.isBufferSource(args[0])) {
      raw = BufferSourceConverter.toArrayBuffer(args[0]);
      options = args[1];
    } else {
      raw = AsnConvert.serialize(
        new AsnExtension({
          extnID: args[0],
          critical: args[1],
          extnValue: new OctetString(BufferSourceConverter.toArrayBuffer(args[2])),
        }),
      );
      options = selfProducedParseOptions;
    }

    super(raw, AsnExtension, options);
  }

  protected onInit(asn: AsnExtension) {
    this.type = asn.extnID;
    this.critical = asn.critical;
    this.value = asn.extnValue.buffer;
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    obj[""] = this.value;

    return obj;
  }

  public toTextObjectWithoutValue(): TextObject {
    const obj = this.toTextObjectEmpty(this.critical ? "critical" : undefined);

    if (obj[TextObject.NAME] === Extension.NAME) {
      obj[TextObject.NAME] = OidSerializer.toString(this.type);
    }

    return obj;
  }
}
