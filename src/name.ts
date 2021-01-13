import { AttributeTypeAndValue, Name as AsnName, RelativeDistinguishedName } from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSourceConverter, Convert } from "pvtsutils";


export interface IdOrName {
  [idOrName: string]: string;
}
export class NameIdentifier {

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

/**
 * UTF-8 String Representation of Distinguished Names
 *
 * https://tools.ietf.org/html/rfc2253
 */
export class Name {

  private extraNames = new NameIdentifier();

  /**
   * ASN.1 Name
   */
  private asn = new AsnName();

  /**
   * Creates a new instance
   * @param data
   * @param extraNames Extra identifiers for name customization
   * @example
   * const text = "URL=http://some.url.com, IP=192.168.0.1, GUID={8ee13e53-2c1c-42bb-8df7-39927c0bdbb6}";
   * const name = new x509.Name(text, {
   *   "Email": "1.2.3.4.5.1",
   *   "IP": "1.2.3.4.5.2",
   *   "GUID": "1.2.3.4.5.3",
   * });
   */
  public constructor(data: BufferSource | AsnName | string | JsonName, extraNames: IdOrName = {}) {
    for (const key in extraNames) {
      if (Object.prototype.hasOwnProperty.call(extraNames, key)) {
        const value = extraNames[key];
        this.extraNames.register(key, value);
      }
    }

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

  private getName(idOrName: string) {
    return this.extraNames.get(idOrName) || names.get(idOrName);
  }

  /**
   * Returns string serialized Name
   */
  public toString() {
    return this.asn.map(rdn =>
      rdn.map(o => {
        const type = this.getName(o.type) || o.type;
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
        const type = this.getName(attr.type) || attr.type;
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

    const regex = /(\d\.[\d.]*\d|[A-Za-z]+)=((?:"")|(?:".*?[^\\]")|(?:[^,+].*?(?:[^\\][,+]))|(?:))([,+])?/g;
    let matches: RegExpExecArray | null = null;
    let level = ",";
    // eslint-disable-next-line no-cond-assign
    while (matches = regex.exec(`${data},`)) {
      let [, type, value] = matches;
      const lastChar = value[value.length-1];
      if (lastChar === "," || lastChar === "+") {
        value = value.slice(0, value.length-1);
        matches[3] = lastChar;
      }
      const next = matches[3];

      // type
      if (!/[\d.]+/.test(type)) {
        type = this.getName(type) || "";
      }
      if (!type) {
        throw new Error(`Cannot get OID for name type '${type}'`);
      }

      // value
      const attr = new AttributeTypeAndValue({ type });

      if (value.charAt(0) === "#") {
        // hexadecimal
        attr.value.anyValue = Convert.FromHex(value.slice(1));
      } else {
        // simple
        const quotedMatches = /"(.*?[^\\])?"/.exec(value);
        if (quotedMatches) {
          // quoted
          value = quotedMatches[1];
        }
        value = value
          .replace(/\\0a/ig, "\n")  // \n
          .replace(/\\0d/ig, "\r")  // \r
          .replace(/\\0g/ig, "\t")  // \t
          .replace(/\\(.)/g, "$1"); // unescape

        if (type === this.getName("E") || type === this.getName("DC")) {
          attr.value.ia5String = value;
        } else {
          attr.value.printableString = value;
        }
      }
      if (level === "+") {
        asn[asn.length - 1].push(attr);
      } else {
        asn.push(new RelativeDistinguishedName([attr]));
      }

      level = next;
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
          typeId = this.getName(type) || "";
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
            if (typeId === this.getName("E") || typeId === this.getName("DC")) {
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