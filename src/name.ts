import { AttributeTypeAndValue, Name as AsnName, RelativeDistinguishedName } from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSourceConverter, Convert } from "pvtsutils";


interface IdOrName {
  [idOrName: string]: string;
}
class NameIdentifier {

  private items: IdOrName = {};

  public get(idOrName: string) {
    return this.items[idOrName] || null;
  }

  public register(id: string, name: string) {
    this.items[id] = name;
    this.items[name] = id;
  }
}

const names = new NameIdentifier();
names.register("CN", "2.5.4.3"); // commonName
names.register("L", "2.5.4.7"); // localityName
names.register("ST", "2.5.4.8"); // stateOrProvinceName
names.register("O", "2.5.4.10"); // organizationName
names.register("OU", "2.5.4.11"); // organizationalUnitName
names.register("C", "2.5.4.6"); // countryName
names.register("DC", "0.9.2342.19200300.100.1.25"); // domainComponent
names.register("E", "1.2.840.113549.1.9.1"); // emailAddress
names.register("G", "2.5.4.42");
names.register("I", "2.5.4.43");
names.register("SN", "2.5.4.4");
names.register("T", "2.5.4.12");

/**
 * JSON representation of Attribute and Value
 */
export interface JsonAttributeAndValue {
  [type: string]: string[];
}

/**
 * JSON array of Attribute and Value
 */
export type JsonName = Array<JsonAttributeAndValue>;

const special = [",", "+", "\"", "\\", "<", ">", ";", "#", " "];

function replaceUnknownCharacter(text: string, char: string) {
  return `\\${Convert.ToHex(Convert.FromUtf8String(char)).toUpperCase()}`;
}

function escape(data: string) {
  return data
    .replace(/([,+"\\<>;])/g, "\\$1") // one of the characters ",", "+", """, "\", "<", ">" or ";"
    .replace(/^([ #])/, "\\$1") // a space or "#" character occurring at the beginning of the string
    .replace(/([ ]$)/, "\\$1") // a space character occurring at the end of the string
    .replace(/([\r\n\t])/, replaceUnknownCharacter) // unknown character
    ;
}

enum ValueType {
  simple,
  quoted,
  hexadecimal,
}

/**
 * UTF-8 String Representation of Distinguished Names
 *
 * https://tools.ietf.org/html/rfc2253
 */
export class Name {

  /**
   * ASN.1 Name
   */
  private asn = new AsnName();

  /**
   * Creates a new instance
   * @param data
   */
  public constructor(data: BufferSource | AsnName | string | JsonName) {
    if (typeof data === "string") {
      this.asn = this.fromString(data);
    } else if (data instanceof AsnName) {
      this.asn = data;
    } else if (BufferSourceConverter.isBufferSource(data)) {
      this.asn = AsnConvert.parse(data, AsnName);
    } else {
      this.asn = this.fromJSON(data);
    }
  }

  /**
   * Returns string serialized Name
   */
  public toString() {
    return this.asn.map(rdn =>
      rdn.map(o => {
        const type = names.get(o.type) || o.type;
        const value = o.value.anyValue
          // If the AttributeValue is of a type which does not have a string
          // representation defined for it, then it is simply encoded as an
          // octothorpe character ('#' ASCII 35) followed by the hexadecimal
          // representation of each of the bytes of the BER encoding of the X.500
          // AttributeValue
          ? `#${Convert.ToHex(o.value.anyValue)}`
          // Otherwise, if the AttributeValue is of a type which has a string
          // representation, the value is converted first to a UTF-8 string
          // according to its syntax specification
          : escape(o.value.toString());
        return `${type}=${value}`;
      })
        .join("+"))
      .join(", ");
  }

  /**
   * Returns a JSON representation of the Name
   */
  public toJSON() {
    const json: JsonName = [];

    for (const rdn of this.asn) {
      const jsonItem: JsonAttributeAndValue = {};
      for (const attr of rdn) {
        const type = names.get(attr.type) || attr.type;
        jsonItem[type] ??= [];
        jsonItem[type].push(attr.value.anyValue ? `#${Convert.ToHex(attr.value.anyValue)}` : attr.value.toString());
      }
      json.push(jsonItem);
    }
    return json;
  }

  /**
   * Creates AsnName object from string
   * @param data
   */
  private fromString(data: string) {
    const asn = new AsnName();

    let subAttribute = false;
    for (let i = 0; i < data.length; i++) {
      let char = data[i];

      // Read type
      let type = "";
      for (i; i < data.length; i++) {
        char = data[i];
        if (char === "=") {
          i++;
          break;
        }
        if (char === " ") {
          continue;
        }
        type += char;
      }
      if (!/[\d.]+/.test(type)) {
        type = names.get(type) || "";
      }
      if (!type) {
        throw new Error(`Cannot get OID for name type '${type}'`);
      }

      // Read value
      let value = "";
      let valueType = ValueType.simple;
      for (i; i < data.length; i++) {
        char = data[i];
        if (value === "") {
          if (char === "#") {
            valueType = ValueType.hexadecimal;
            continue;
          } else if (char === "\"") {
            valueType = ValueType.quoted;
            continue;
          }
        }

        if (valueType === ValueType.quoted && char === "\"") {
          // read till comma or plus character
          while (i++ < data.length) {
            char = data[i];
            if (data === "," || char === '+') {
              break;
            }
            if (data === " ") {
              continue;
            }
            throw new Error("Cannot parse name from string. Incorrect character after quoted attribute value");
          }
          break;
        } else if ((valueType === ValueType.simple || valueType === ValueType.hexadecimal) && (char === "," || char === '+')) {
          break;
        }

        // escaped character
        if (char === "\\") {
          char = data[++i];
          if (!special.includes(char)) {
            const hex = `${data[i++]}${data[i]}`;
            if (!/[0-9a-f]{2}/i.test(hex)) {
              throw new Error("Cannot parse name from string. Escaped hexadecimal value doesn't match to regular pattern");
            }
            char = String.fromCharCode(parseInt(hex, 16));
          }
        }

        value += char;

      }

      const attr = new AttributeTypeAndValue({ type });
      if (valueType === ValueType.hexadecimal) {
        attr.value.anyValue = Convert.FromHex(value);
      } else {
        if (type === names.get("E") || type === names.get("DC")) {
          attr.value.ia5String = value;
        } else {
          attr.value.printableString = value;
        }
      }
      if (subAttribute) {
        asn[asn.length - 1].push(attr);
      } else {
        asn.push(new RelativeDistinguishedName([attr]));
      }
      subAttribute = char === "+";
    }

    return asn;
  }

  /**
   * Creates AsnName from JSON
   * @param data
   */
  private fromJSON(data: JsonName): AsnName {
    const asn = new AsnName();

    for (const item of data) {
      const asnRdn = new RelativeDistinguishedName();
      for (const type in item) {
        let typeId = type;
        if (!/[\d.]+/.test(type)) {
          typeId = names.get(type) || "";
        }
        if (!typeId) {
          throw new Error(`Cannot get OID for name type '${type}'`);
        }

        const values = item[type];
        for (const value of values) {
          const asnAttr = new AttributeTypeAndValue({ type: typeId });
          if (value[0] === "#") {
            asnAttr.value.anyValue = Convert.FromHex(value.slice(1));
          } else {
            if (typeId === names.get("E") || typeId === names.get("DC")) {
              asnAttr.value.ia5String = value;
            } else {
              asnAttr.value.printableString = value;
            }
          }
          asnRdn.push(asnAttr);
        }
      }

      asn.push(asnRdn);
    }

    return asn;
  }

  /**
   * Returns Name in DER encoded format
   */
  public toArrayBuffer() {
    return AsnConvert.serialize(this.asn);
  }

}