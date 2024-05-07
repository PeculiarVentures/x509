import { OctetString } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import * as ocsp from "@peculiar/asn1-ocsp";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { TextObject } from "../text_converter";



/**
 * Represents the Nonce OCSP extension
 */
export class NonceExtension extends Extension {

  public static override NAME = "Nonce";
  public extID!: string;
  public extValue!: OctetString;
  public critical!: boolean;
  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param data list of access descriptions
   * @param critical Indicates where extension is critical. Default is `false`
   */
  public constructor(nonce: Uint8Array | string, critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(ocsp.id_pkix_ocsp_nonce, args[1], args[0]);

    } else {
        // convert string to Uint8Array
        const encoder = new TextEncoder();
        super(ocsp.id_pkix_ocsp_nonce, args[1], encoder.encode(args[0]));
    }
  }

  onInit(asn: asn1X509.Extension) {
    this.extID = asn.extnID;
    this.extValue = asn.extnValue;
    this.critical = asn.critical;
  }

  public override toTextObject(): TextObject {

    const obj = this.toTextObjectWithoutValue();
    // new TextDecoder().decode(this.extValue);
    obj[this.extID] = new TextDecoder().decode(this.extValue.buffer);

    return obj;
  }
}
