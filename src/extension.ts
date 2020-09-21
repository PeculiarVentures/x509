import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { Extension as AsnExtension } from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { AsnData } from "./asn_data";

/**
 * Represents the certificate extension
 */
export class Extension extends AsnData<AsnExtension>{

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
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param type Extension identifier
   * @param critical Indicates where extension is critical
   * @param value DER encoded value of extension
   */
  public constructor(type: string, critical: boolean, value: BufferSource);
  public constructor(...args: any[]) {
    let raw: ArrayBuffer;
    if (BufferSourceConverter.isBufferSource(args[0])) {
      raw = BufferSourceConverter.toArrayBuffer(args[0]);
    } else {
      raw = AsnConvert.serialize(new AsnExtension({
        extnID: args[0],
        critical: args[1],
        extnValue: new OctetString(BufferSourceConverter.toArrayBuffer(args[2])),
      }));
    }

    super(raw, AsnExtension);
  }

  protected onInit(asn: AsnExtension) {
    this.type = asn.extnID;
    this.critical = asn.critical;
    this.value = asn.extnValue.buffer;
  }
}
