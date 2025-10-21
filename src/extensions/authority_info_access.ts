import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { TextObject } from "../text_converter";
import { GeneralName } from "../general_name";

export type AccessItemTypes = GeneralName | GeneralName[] | string | string[];
export interface AuthorityInfoAccessParams {
  ocsp?: AccessItemTypes;
  caIssuers?: AccessItemTypes;
  timeStamping?: AccessItemTypes;
  caRepository?: AccessItemTypes;
}

/**
 * Represents the Authority Info Access certificate extension
 */
export class AuthorityInfoAccessExtension extends Extension {
  public static override NAME = "Authority Info Access";

  public ocsp: GeneralName[];
  public caIssuers: GeneralName[];
  public timeStamping: GeneralName[];
  public caRepository: GeneralName[];

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param value The value of the extension
   * @param critical Indicates whether the extension is critical. Default is `false`
   */
  public constructor(value: asn1X509.AuthorityInfoAccessSyntax, critical?: boolean);
  /**
   * Creates a new instance
   * @param params The value of the extension
   * @param critical Indicates whether the extension is critical. Default is `false`
   */
  public constructor(params: AuthorityInfoAccessParams, critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0] as BufferSource);
    } else if (args[0] instanceof asn1X509.AuthorityInfoAccessSyntax) {
      const value = new asn1X509.AuthorityInfoAccessSyntax(args[0]);
      super(asn1X509.id_pe_authorityInfoAccess, args[1], AsnConvert.serialize(value));
    } else {
      const params = args[0] as AuthorityInfoAccessParams;
      const value = new asn1X509.AuthorityInfoAccessSyntax();

      addAccessDescriptions(value, params, asn1X509.id_ad_ocsp, "ocsp");
      addAccessDescriptions(value, params, asn1X509.id_ad_caIssuers, "caIssuers");
      addAccessDescriptions(value, params, asn1X509.id_ad_timeStamping, "timeStamping");
      addAccessDescriptions(value, params, asn1X509.id_ad_caRepository, "caRepository");

      super(asn1X509.id_pe_authorityInfoAccess, args[1], AsnConvert.serialize(value));
    }

    this.ocsp ??= [];
    this.caIssuers ??= [];
    this.timeStamping ??= [];
    this.caRepository ??= [];
  }

  protected onInit(asn: asn1X509.Extension) {
    super.onInit(asn);

    this.ocsp = [];
    this.caIssuers = [];
    this.timeStamping = [];
    this.caRepository = [];

    const aia = AsnConvert.parse(asn.extnValue, asn1X509.AuthorityInfoAccessSyntax);
    aia.forEach((accessDescription) => {
      switch (accessDescription.accessMethod) {
        case asn1X509.id_ad_ocsp:
          this.ocsp.push(new GeneralName(accessDescription.accessLocation));
          break;
        case asn1X509.id_ad_caIssuers:
          this.caIssuers.push(new GeneralName(accessDescription.accessLocation));
          break;
        case asn1X509.id_ad_timeStamping:
          this.timeStamping.push(new GeneralName(accessDescription.accessLocation));
          break;
        case asn1X509.id_ad_caRepository:
          this.caRepository.push(new GeneralName(accessDescription.accessLocation));
          break;
        default:
          // Handle unknown access methods if necessary
          break;
      }
    });
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    if (this.ocsp.length) {
      addUrlsToObject(obj, "OCSP", this.ocsp);
    }

    if (this.caIssuers.length) {
      addUrlsToObject(obj, "CA Issuers", this.caIssuers);
    }

    if (this.timeStamping.length) {
      addUrlsToObject(obj, "Time Stamping", this.timeStamping);
    }

    if (this.caRepository.length) {
      addUrlsToObject(obj, "CA Repository", this.caRepository);
    }

    return obj;
  }
}

function addUrlsToObject(obj: TextObject, key: string, urls: GeneralName[]) {
  if (urls.length === 1) {
    obj[key] = urls[0].toTextObject();
  } else {
    const names = new TextObject("");
    urls.forEach((name, index) => {
      const nameObj = name.toTextObject();
      const indexedKey = `${nameObj[TextObject.NAME]} ${index + 1}`;
      let field = names[indexedKey];
      if (!Array.isArray(field)) {
        field = [];
        names[indexedKey] = field;
      }

      field.push(nameObj);
    });
    obj[key] = names;
  }
}

function addAccessDescriptions(
  value: asn1X509.AuthorityInfoAccessSyntax,
  params: AuthorityInfoAccessParams,
  method: string,
  key: keyof AuthorityInfoAccessParams,
) {
  const items = params[key];
  if (items) {
    const array = Array.isArray(items) ? items : [items];
    array.forEach((url) => {
      if (typeof url === "string") {
        url = new GeneralName("url", url);
      }
      value.push(new asn1X509.AccessDescription({
        accessMethod: method,
        accessLocation: AsnConvert.parse(url.rawData, asn1X509.GeneralName),
      }));
    });
  }
}
