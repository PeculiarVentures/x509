import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { TextObject } from "../text_converter";
import { GeneralName } from "../general_name";

/**
 * Represents interface for AccessDescription
 */
interface AccessDescriptionInterface {
  method: string,
  location: string | undefined
}

/**
 * Represents the Authority Information Access certificate extension
 */
export class AuthorityInformationAccessExtension extends Extension {

  public static override NAME = "Authority Information Access";

  public data!: AccessDescriptionInterface[];
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
  public constructor(data: AccessDescriptionInterface[], critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);
    } else {

      // parse args into AuthorityInfoAccessSyntax
      const accessDescriptions = [];
      for(const accessDescription of args[0]){
        accessDescriptions.push(new asn1X509.AccessDescription({
          accessMethod: accessDescription.method,
          // if location is undefined, pass "" to generalName
          accessLocation: (accessDescription.location === undefined) ?
            new asn1X509.GeneralName({uniformResourceIdentifier: ""}) :
            new asn1X509.GeneralName({uniformResourceIdentifier: accessDescription.location})
        }));
      }

      super(asn1X509.id_pe_authorityInfoAccess, args[1], AsnConvert.serialize(new asn1X509.AuthorityInfoAccessSyntax(accessDescriptions)));
    }
  }

  onInit(asn: asn1X509.Extension) {
    super.onInit(asn);
    const collector = [];
    const value = AsnConvert.parse(asn.extnValue, asn1X509.AuthorityInfoAccessSyntax);
    // parse AuthorityInfoAccessSyntax into access descriptions
    for(const accessDescription of value){
      collector.push({
        method: accessDescription.accessMethod,
        location: accessDescription.accessLocation.uniformResourceIdentifier
      });
    }
    this.data = collector;
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    // parse access descriptions into text
    // convert method value to ocsp/issuer text
    for (const accessDescription of this.data) {
      // if location is undefined, set obj[accessDescription.method] to ""
      // otherwise, set obj[accessDescription.method] to location
      if(accessDescription.location === undefined){
        obj[accessDescription.method] = new GeneralName("url", "").toTextObject();
      }else{
        obj[accessDescription.method] = new GeneralName("url", accessDescription.location).toTextObject();
      }
    }

    return obj;
  }
}