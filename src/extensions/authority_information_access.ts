import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { GeneralNames, JsonGeneralNames } from "../general_name";
import { TextObject } from "../text_converter";

export type AuthorityInfoAccessType = asn1X509.AuthorityInfoAccessSyntax | string;
/**
 * Represents the Authority Information Access certificate extension
 */
export class AuthorityInformationAccessExtension extends Extension {


  public static override NAME = "Authority Information Access";

  public data!: AuthorityInfoAccessType;
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
  public constructor(data?: AuthorityInfoAccessType, critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);
    } else {
      super(asn1X509.id_ce_subjectAltName, args[1], new GeneralNames(args[0] || []).rawData);
    }
  }

  onInit(asn: asn1X509.Extension) {
    super.onInit(asn);
    // On Init code here
    this.data = AsnConvert.parse(asn.extnValue, asn1X509.AuthorityInfoAccessSyntax);
  }



}