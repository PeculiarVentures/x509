import { AttributeTypeAndValue, Name as AsnName, RelativeDistinguishedName } from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { cryptoProvider } from "./provider";

const OID_REGEX = /^[0-2](?:\.[1-9][0-9]*)+$/;

function isOID(id: string) {
  return new RegExp(OID_REGEX).test(id);
}


export interface IdOrName {
  [idOrName: string]: string;
}
export class NameIdentifier {

  private items: IdOrName = {};

  public constructor(names: Record<string, string> = {}) {
    for (const id in names) {
      this.register(id, names[id]);
    }
  }

  public get(idOrName: string): string | null {
    return this.items[idOrName] || null;
  }

  public findId(idOrName: string): string | null {
    if (!isOID(idOrName)) {
      return this.get(idOrName);
    }

    return idOrName;
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
export interface JsonAttributeAndStringValue {
  [type: string]: string[];
}

export interface JsonAttributeObject {
  ia5String?: string;
  utf8String?: string;
  universalString?: string;
  bmpString?: string;
  printableString?: string;
}

export interface JsonAttributeAndObjectValue {
  [type: string]: JsonAttributeObject[];
}

export type JsonAttributeAndValue = JsonAttributeAndStringValue | JsonAttributeAndObjectValue;

/**
 * JSON array of Attribute and Value
 */
export type JsonName = Array<JsonAttributeAndStringValue>;

export type JsonNameParams = Array<JsonAttributeAndValue>;

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
   * Returns `true` if text is ASCII otherwise `false`
   * @param text Text
   * @returns
   */
  public static isASCII(text: string) {
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code > 0xFF) {
        return false;
      }
    }

    return true;
  }

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
  public constructor(data: BufferSource | AsnName | string | JsonNameParams, extraNames: IdOrName = {}) {
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

  /**
   * Returns a list of string values filtered by specified id or name
   * @param idOrName ObjectIdentifier or string name
   * @returns Returns a list of strings. Returns an empty list if there are not any values for specified id/name.
   */
  public getField(idOrName: string): string[] {
    const id = this.extraNames.findId(idOrName) || names.findId(idOrName);
    const res: string[] = [];

    for (const name of this.asn) {
      for (const rdn of name) {
        if (rdn.type === id) {
          res.push(rdn.value.toString());
        }
      }
    }

    return res;
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
  public toJSON(): JsonName {
    const json: JsonName = [];

    for (const rdn of this.asn) {
      const jsonItem: JsonAttributeAndStringValue = {};
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
      const lastChar = value[value.length - 1];
      if (lastChar === "," || lastChar === "+") {
        value = value.slice(0, value.length - 1);
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
          // Use Utf8String for non ASCII strings
          if (Name.isASCII(value)) {
            attr.value.printableString = value;
          } else {
            attr.value.utf8String = value;
          }
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
  private fromJSON(data: JsonNameParams): AsnName {
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
          if (typeof value === "object") {
            for (const key in value) {
              switch (key) {
                case "ia5String": asnAttr.value.ia5String = value[key]; break;
                case "utf8String": asnAttr.value.utf8String = value[key]; break;
                case "universalString": asnAttr.value.universalString = value[key]; break;
                case "bmpString": asnAttr.value.bmpString = value[key]; break;
                case "printableString": asnAttr.value.printableString = value[key]; break;
              }
            }
          } else if (value[0] === "#") {
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

  /**
   * Returns a SHA-1 thumbprint
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async getThumbprint(crypto?: Crypto): Promise<ArrayBuffer>;
  /**
   * Returns a thumbprint for specified mechanism
   * @param algorithm Hash algorithm
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async getThumbprint(algorithm: globalThis.AlgorithmIdentifier, crypto?: Crypto): Promise<ArrayBuffer>;
  public async getThumbprint(...args: any[]) {
    let crypto: Crypto;
    let algorithm = "SHA-1";

    if (args.length >= 1 && !args[0]?.subtle) {
      // crypto?
      algorithm = args[0] || algorithm;
      crypto = args[1] || cryptoProvider.get();
    } else {
      crypto = args[0] || cryptoProvider.get();
    }

    return await crypto.subtle.digest(algorithm, this.toArrayBuffer());
  }

}