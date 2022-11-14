import { AsnConvert, AsnUtf8StringConverter, OctetString } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { AsnData } from "./asn_data";
import { Name } from "./name";
import { OidSerializer, TextObject } from "./text_converter";

const ERR_GN_CONSTRUCTOR = "Cannot initialize GeneralName from ASN.1 data.";
const ERR_GN_STRING_FORMAT = `${ERR_GN_CONSTRUCTOR} Unsupported string format in use.`;
const ERR_GUID = `${ERR_GN_CONSTRUCTOR} Value doesn't match to GUID regular expression.`;

const GUID_REGEX = /^([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{12})$/i;

const id_GUID = "1.3.6.1.4.1.311.25.1";
const id_UPN = "1.3.6.1.4.1.311.20.2.3";

export interface JsonGeneralName {
  type: GeneralNameType;
  value: string;
}

const DNS = "dns";
const DN = "dn";
const EMAIL = "email";
const IP = "ip";
const URL = "url";
const GUID = "guid";
const UPN = "upn";
const REGISTERED_ID = "id";

export type GeneralNameType = typeof DNS | typeof DN | typeof EMAIL | typeof GUID | typeof IP | typeof URL | typeof UPN | typeof REGISTERED_ID;

/**
 * Represents ASN.1 type of GeneralName.
 *
 * This class doesn't support no standard string format is defined for otherName, X.400 name, EDI party name, or any other type of names.
 */
export class GeneralName extends AsnData<asn1X509.GeneralName> {

  /**
   * Type of the storing value
   */
  public type!: GeneralNameType;
  /**
   * Text representation of ASN.1 GeneralName
   */
  public value!: string;

  public constructor(type: GeneralNameType, value: string);
  public constructor(asn: asn1X509.GeneralName);
  public constructor(raw: BufferSource);
  public constructor(...args: any[]) {
    let name: asn1X509.GeneralName;
    if (args.length === 2) {
      // type: GeneralNameType, value: string
      switch (args[0] as GeneralNameType) {
        case DN: {
          const derName = new Name(args[1]).toArrayBuffer();
          const asnName = AsnConvert.parse(derName, asn1X509.Name);
          name = new asn1X509.GeneralName({ directoryName: asnName });
          break;
        }
        case DNS:
          name = new asn1X509.GeneralName({ dNSName: args[1] });
          break;
        case EMAIL:
          name = new asn1X509.GeneralName({ rfc822Name: args[1] });
          break;
        case GUID: {
          const matches = new RegExp(GUID_REGEX, "i").exec(args[1]);
          if (!matches) {
            throw new Error("Cannot parse GUID value. Value doesn't match to regular expression");
          }
          const hex = matches
            .slice(1)
            .map((o, i) => {
              if (i < 3) {
                return Convert.ToHex(new Uint8Array(Convert.FromHex(o)).reverse());
              }

              return o;
            })
            .join("");

          name = new asn1X509.GeneralName({
            otherName: new asn1X509.OtherName({
              typeId: id_GUID,
              value: AsnConvert.serialize(new OctetString(Convert.FromHex(hex))),
            }),
          });
          break;
        }
        case IP:
          name = new asn1X509.GeneralName({ iPAddress: args[1] });
          break;
        case REGISTERED_ID:
          name = new asn1X509.GeneralName({ registeredID: args[1] });
          break;
        case UPN: {
          name = new asn1X509.GeneralName({
            otherName: new asn1X509.OtherName({
              typeId: id_UPN,
              value: AsnConvert.serialize(AsnUtf8StringConverter.toASN(args[1])),
            })
          });
          break;
        }
        case URL:
          name = new asn1X509.GeneralName({ uniformResourceIdentifier: args[1] });
          break;
        default:
          throw new Error("Cannot create GeneralName. Unsupported type of the name");
      }
    } else if (BufferSourceConverter.isBufferSource(args[0])) {
      // raw: BufferSource
      name = AsnConvert.parse(args[0], asn1X509.GeneralName);
    } else {
      // asn: asn1X509.GeneralName
      name = args[0];
    }
    super(name);
  }

  /**
   * Occurs on instance initialization
   * @param asn
   *
   * @throws Throws error if ASN.1 GeneralName contains unsupported value (eg otherName, X400 address, EDI party name)
   */
  protected onInit(asn: asn1X509.GeneralName): void {
    if (asn.dNSName != undefined) {
      this.type = DNS;
      this.value = asn.dNSName;
    } else if (asn.rfc822Name != undefined) {
      this.type = EMAIL;
      this.value = asn.rfc822Name;
    } else if (asn.iPAddress != undefined) {
      this.type = IP;
      this.value = asn.iPAddress;
    } else if (asn.uniformResourceIdentifier != undefined) {
      this.type = URL;
      this.value = asn.uniformResourceIdentifier;
    } else if (asn.registeredID != undefined) {
      this.type = REGISTERED_ID;
      this.value = asn.registeredID;
    } else if (asn.directoryName != undefined) {
      this.type = DN;
      this.value = new Name(asn.directoryName).toString();
    } else if (asn.otherName != undefined) {
      if (asn.otherName.typeId === id_GUID) {
        this.type = GUID;
        const guid = AsnConvert.parse(asn.otherName.value, OctetString);
        const matches = new RegExp(GUID_REGEX, "i").exec(Convert.ToHex(guid));
        if (!matches) {
          throw new Error(ERR_GUID);
        }
        this.value = matches
          .slice(1)
          .map((o, i) => {
            if (i < 3) {
              return Convert.ToHex(new Uint8Array(Convert.FromHex(o)).reverse());
            }

            return o;
          })
          .join("-");
      } else if (asn.otherName.typeId === id_UPN) {
        this.type = UPN;
        this.value = AsnConvert.parse(asn.otherName.value, asn1X509.DirectoryString).toString();
      } else {
        throw new Error(ERR_GN_STRING_FORMAT);
      }
    } else {
      throw new Error(ERR_GN_STRING_FORMAT);
    }

  }

  public toJSON(): JsonGeneralName {
    return {
      type: this.type,
      value: this.value,
    };
  }

  public override toTextObject(): TextObject {
    let type: string;
    switch (this.type) {
      case DN:
      case DNS:
      case GUID:
      case IP:
      case REGISTERED_ID:
      case UPN:
      case URL:
        type = this.type.toUpperCase();
        break;
      case EMAIL:
        type = "Email";
        break;
      default:
        throw new Error("Unsupported GeneralName type");
    }

    let value = this.value;
    if (this.type === REGISTERED_ID) {
      value = OidSerializer.toString(value);
    }

    return new TextObject(type, undefined, value);
  }

}

export type JsonGeneralNames = JsonGeneralName[];

export class GeneralNames extends AsnData<asn1X509.GeneralNames> {
  public static override NAME = "GeneralNames";

  public items!: ReadonlyArray<GeneralName>;

  constructor(json: JsonGeneralNames);
  constructor(asn: asn1X509.GeneralNames | asn1X509.GeneralName[]);
  constructor(raw: BufferSource);
  constructor(params: JsonGeneralNames | asn1X509.GeneralNames | asn1X509.GeneralName[] | BufferSource) {
    let names: asn1X509.GeneralNames;
    if (params instanceof asn1X509.GeneralNames) {
      // asn1X509.GeneralNames
      names = params;
    } else if (Array.isArray(params)) {
      // JsonGeneralNames[] | asn1X509.GeneralName[]
      const items: asn1X509.GeneralName[] = [];

      for (const name of params) {
        if (name instanceof asn1X509.GeneralName) {
          items.push(name);
        } else {
          const asnName = AsnConvert.parse(new GeneralName(name.type, name.value).rawData, asn1X509.GeneralName);
          items.push(asnName);
        }
      }

      names = new asn1X509.GeneralNames(items);
    } else if (BufferSourceConverter.isBufferSource(params)) {
      names = AsnConvert.parse(params, asn1X509.GeneralNames);
    } else {
      throw new Error("Cannot initialize GeneralNames. Incorrect incoming arguments");
    }

    super(names);
  }

  protected onInit(asn: asn1X509.GeneralNames): void {
    const items: GeneralName[] = [];
    for (const asnName of asn) {
      let name: GeneralName | null = null;
      try {
        name = new GeneralName(asnName);
      } catch {
        // skip unsupported ASN.1 GeneralName
        continue;
      }
      items.push(name);
    }

    this.items = items;
  }

  public toJSON(): JsonGeneralNames {
    return this.items.map(o => o.toJSON());
  }

  public override toTextObject(): TextObject {
    const res = super.toTextObjectEmpty();

    for (const name of this.items) {
      const nameObj = name.toTextObject();
      let field = res[nameObj[TextObject.NAME]];
      if (!Array.isArray(field)) {
        field = [];
        res[nameObj[TextObject.NAME]] = field;
      }

      field.push(nameObj);
    }

    return res;
  }

}