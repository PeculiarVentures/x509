import { Attribute as AsnAttribute } from "@peculiar/asn1-x509";
import { AsnData } from "./asn_data";

/**
 * Represents the Attribute structure
 */
export class Attribute extends AsnData<AsnAttribute>{

  /**
   * Gets an attribute identifier
   */
  public type!: string;

  /**
   * Gets a list of DER encoded attribute values
   */
  public values!: ArrayBuffer[];

  /**
   * Crates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource) {
    super(raw, AsnAttribute);
  }

  protected onInit(asn: AsnAttribute): void {
    this.type = asn.type;
    this.values = asn.values;
  }
}
