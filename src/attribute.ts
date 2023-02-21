import { AsnConvert } from "@peculiar/asn1-schema";
import { Attribute as AsnAttribute } from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { AsnData } from "./asn_data";
import { OidSerializer, TextObject } from "./text_converter";

/**
 * Represents the Attribute structure
 */
export class Attribute extends AsnData<AsnAttribute>{

  public static override NAME = "Attribute";

  /**
   * Gets an attribute identifier
   */
  public type!: string;

  /**
   * Gets a list of DER encoded attribute values
   */
  public values!: ArrayBuffer[];

  /**
   * Crates a new instance
   * @param type Attribute identifier
   * @param values List of DER encoded attribute values
   */
  public constructor(type: string, values?: BufferSource[]);
  /**
   * Crates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  public constructor(...args: any[]) {
    let raw: ArrayBuffer;
    if (BufferSourceConverter.isBufferSource(args[0])) {
      raw = BufferSourceConverter.toArrayBuffer(args[0]);
    } else {
      const type = args[0];
      const values = Array.isArray(args[1]) ? args[1].map(o => BufferSourceConverter.toArrayBuffer(o)) : [];
      raw = AsnConvert.serialize(new AsnAttribute({ type, values }));
    }

    super(raw, AsnAttribute);
  }

  protected onInit(asn: AsnAttribute): void {
    this.type = asn.type;
    this.values = asn.values;
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    obj["Value"] = this.values.map(o => new TextObject("", { "": o }));

    return obj;
  }

  public toTextObjectWithoutValue(): TextObject {
    const obj = this.toTextObjectEmpty();

    if (obj[TextObject.NAME] === Attribute.NAME) {
      obj[TextObject.NAME] = OidSerializer.toString(this.type);
    }

    return obj;
  }
}
