import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { GeneralNames, JsonGeneralNames } from "../general_name";
import { TextObject } from "../text_converter";

/**
 * Represents the Subject Alternative Name certificate extension
 */
export class SubjectAlternativeNameExtension extends Extension {

  public names!: GeneralNames;

  public static override NAME = "Subject Alternative Name";

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param data JSON representation of SAN
   * @param critical Indicates where extension is critical. Default is `false`
   */
  public constructor(data?: JsonGeneralNames, critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);
    } else {
      super(asn1X509.id_ce_subjectAltName, args[1], new GeneralNames(args[0] || []).rawData);
    }
  }

  onInit(asn: asn1X509.Extension) {
    super.onInit(asn);

    // value
    const value = AsnConvert.parse(asn.extnValue, asn1X509.SubjectAlternativeName);

    this.names = new GeneralNames(value);
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    const namesObj = this.names.toTextObject();
    for (const key in namesObj) {
      obj[key] = namesObj[key];
    }

    return obj;
  }

}
