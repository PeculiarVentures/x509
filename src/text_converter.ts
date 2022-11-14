import * as asn1Cms from "@peculiar/asn1-cms";
import * as asn1Ecc from "@peculiar/asn1-ecc";
import * as asn1Rsa from "@peculiar/asn1-rsa";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { EcAlgorithm } from "./ec_algorithm";

export interface TextObjectConvertible {
  /**
   * Returns the object in textual representation
   */
  toTextObject(): TextObject;
}

export type TextObjectItemType = string | number | boolean | Date | BufferSource | TextObject | TextObject[] | TextObjectConvertible;

const NAME = Symbol("name");
const VALUE = Symbol("value");
export class TextObject {

  public static NAME: typeof NAME = NAME;
  public static VALUE: typeof VALUE = VALUE;

  [key: string | symbol]: TextObjectItemType;
  public [NAME]: string;
  public [VALUE]: string;

  constructor(name: string, items: Record<string, TextObjectItemType> = {}, value = "") {
    this[NAME] = name;
    this[VALUE] = value;

    for (const key in items) {
      this[key] = items[key];
    }
  }
}

export interface AlgorithmSerializer {
  toTextObject(alg: asn1X509.AlgorithmIdentifier): TextObject;
}

export abstract class DefaultAlgorithmSerializer {
  public static toTextObject(alg: asn1X509.AlgorithmIdentifier): TextObject {
    const obj = new TextObject("Algorithm Identifier", {}, OidSerializer.toString(alg.algorithm));

    if (alg.parameters) {
      switch (alg.algorithm) {
        case asn1Ecc.id_ecPublicKey: {
          const ecAlg = new EcAlgorithm().toWebAlgorithm(alg);
          if (ecAlg && "namedCurve" in ecAlg) {
            obj["Named Curve"] = ecAlg.namedCurve;
          } else {
            obj["Parameters"] = alg.parameters;
          }
          break;
        }
        default:
          obj["Parameters"] = alg.parameters;
      }
    }

    return obj;
  }

}

export abstract class OidSerializer {

  public static items: Record<string, string> = {
    [asn1Rsa.id_sha1]: "sha1",
    [asn1Rsa.id_sha224]: "sha224",
    [asn1Rsa.id_sha256]: "sha256",
    [asn1Rsa.id_sha384]: "sha384",
    [asn1Rsa.id_sha512]: "sha512",
    [asn1Rsa.id_rsaEncryption]: "rsaEncryption",
    [asn1Rsa.id_sha1WithRSAEncryption]: "sha1WithRSAEncryption",
    [asn1Rsa.id_sha224WithRSAEncryption]: "sha224WithRSAEncryption",
    [asn1Rsa.id_sha256WithRSAEncryption]: "sha256WithRSAEncryption",
    [asn1Rsa.id_sha384WithRSAEncryption]: "sha384WithRSAEncryption",
    [asn1Rsa.id_sha512WithRSAEncryption]: "sha512WithRSAEncryption",
    [asn1Ecc.id_ecPublicKey]: "ecPublicKey",
    [asn1Ecc.id_ecdsaWithSHA1]: "ecdsaWithSHA1",
    [asn1Ecc.id_ecdsaWithSHA224]: "ecdsaWithSHA224",
    [asn1Ecc.id_ecdsaWithSHA256]: "ecdsaWithSHA256",
    [asn1Ecc.id_ecdsaWithSHA384]: "ecdsaWithSHA384",
    [asn1Ecc.id_ecdsaWithSHA512]: "ecdsaWithSHA512",
    [asn1X509.id_kp_serverAuth]: "TLS WWW server authentication",
    [asn1X509.id_kp_clientAuth]: "TLS WWW client authentication",
    [asn1X509.id_kp_codeSigning]: "Code Signing",
    [asn1X509.id_kp_emailProtection]: "E-mail Protection",
    [asn1X509.id_kp_timeStamping]: "Time Stamping",
    [asn1X509.id_kp_OCSPSigning]: "OCSP Signing",
    [asn1Cms.id_signedData]: "Signed Data",
  };

  public static toString(oid: string): string {
    const name = this.items[oid];
    if (name) {
      return name;
    }

    return oid;
  }
}

export abstract class TextConverter {

  public static oidSerializer = OidSerializer;
  public static algorithmSerializer: AlgorithmSerializer = DefaultAlgorithmSerializer;

  public static serialize(obj: TextObject): string {
    return this.serializeObj(obj).join("\n");
  }

  private static pad(deep = 0): string {
    return "".padStart(2 * deep, " ");
  }

  private static serializeObj(obj: TextObject, deep = 0): string[] {
    const res: string[] = [];
    let pad = this.pad(deep++);

    let value = "";
    const objValue = obj[TextObject.VALUE];
    if (objValue) {
      value = ` ${objValue}`;
    }

    res.push(`${pad}${obj[TextObject.NAME]}:${value}`); // object name:
    pad = this.pad(deep);

    for (const key in obj) {
      if (typeof key === "symbol") {
        continue;
      }

      const value = obj[key];
      const keyValue = key ? `${key}: ` : "";
      if (typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean") {
        res.push(`${pad}${keyValue}${value}`); // key: value
      } else if (value instanceof Date) {
        res.push(`${pad}${keyValue}${value.toUTCString()}`); // key: UTC(date)
      } else if (Array.isArray(value)) {
        for (const obj of value) {
          obj[TextObject.NAME] = key;
          res.push(...this.serializeObj(obj, deep));
        }
      } else if (value instanceof TextObject) {
        value[TextObject.NAME] = key;
        res.push(...this.serializeObj(value, deep));
      } else if (BufferSourceConverter.isBufferSource(value)) {
        if (key) {
          res.push(`${pad}${keyValue}`);
          res.push(...this.serializeBufferSource(value, deep + 1));
        } else {
          res.push(...this.serializeBufferSource(value, deep));
        }
      } else if ("toTextObject" in value) {
        const obj = value.toTextObject();
        obj[TextObject.NAME] = key;
        res.push(...this.serializeObj(obj, deep));
      } else {
        throw new TypeError("Cannot serialize data in text format. Unsupported type.");
      }
    }

    return res;
  }

  private static serializeBufferSource(buffer: BufferSource, deep = 0): string[] {
    const pad = this.pad(deep);
    const view = BufferSourceConverter.toUint8Array(buffer);

    const res: string[] = [];

    // each hex raw should have 16 octets
    for (let i = 0; i < view.length;) {
      const row: string[] = [];
      for (let j = 0; j < 16 && i < view.length; j++) {
        if (j === 8) {
          row.push(""); // split hex columns
        }

        const hex = view[i++].toString(16).padStart(2, "0");
        row.push(hex);
      }
      res.push(`${pad}${row.join(" ")}`);
    }

    return res;
  }

  public static serializeAlgorithm(alg: asn1X509.AlgorithmIdentifier): TextObject {
    return this.algorithmSerializer.toTextObject(alg);
  }

}
