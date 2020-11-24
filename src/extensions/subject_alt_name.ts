import { AsnConvert, AsnUtf8StringConverter, OctetString } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { AsnData } from "../asn_data";
import { Extension } from "../extension";

export interface JsonOtherName {
  type: string;
  /**
   * Hexadecimal representation of the value
   */
  value: string;
}
export interface JsonSubjectAlternativeName {
  dns?: string[];
  email?: string[];
  guid?: string[];
  ip?: string[];
  url?: string[];
  upn?: string[];
  registeredId?: string[];
  otherName?: JsonOtherName[];
}

export class OtherName extends AsnData<asn1X509.OtherName> {

  public type!: string;

  public value!: ArrayBuffer;

  /**
   * Crates a new instance
   * @param type Other name identifier
   * @param value DER encoded value
   */
  public constructor(type: string, value: BufferSource);
  /**
   * Crates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  public constructor(...args: any[]) {
    let raw: ArrayBuffer;
    if (BufferSourceConverter.isBufferSource(args[0])) {
      raw = BufferSourceConverter.toArrayBuffer(args[0]);
    } else {
      const type = args[0];
      const value = BufferSourceConverter.toArrayBuffer(args[1]);
      raw = AsnConvert.serialize(new asn1X509.OtherName({ typeId: type, value }));
    }

    super(raw, asn1X509.OtherName);
  }

  protected onInit(asn: asn1X509.OtherName): void {
    this.type = asn.typeId;
    this.value = asn.value;
  }

  public toJSON(): JsonOtherName {
    return {
      type: this.type,
      value: Convert.ToHex(this.value),
    };
  }

}

/**
 * Represents the Subject Alternative Name certificate extension
 */
export class SubjectAlternativeNameExtension extends Extension {

  public static GUID = "1.3.6.1.4.1.311.25.1";
  public static UPN = "1.3.6.1.4.1.311.20.2.3";

  public dns!: string[];
  public email!: string[];
  public guid!: string[];
  public ip!: string[];
  public url!: string[];
  public upn!: string[];
  public otherNames!: OtherName[];
  public registeredId!: string[];

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
  public constructor(data?: JsonSubjectAlternativeName, critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);
    } else {
      const data: JsonSubjectAlternativeName = args[0] || {};

      const value = new asn1X509.SubjectAlternativeName();

      // DNS
      for (const item of data.dns || []) {
        value.push(new asn1X509.GeneralName({
          dNSName: item,
        }));
      }
      // email
      for (const item of data.email || []) {
        value.push(new asn1X509.GeneralName({
          rfc822Name: item,
        }));
      }
      // guid
      for (const item of data.guid || []) {
        const matches = /([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{12})/i.exec(item);
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

        value.push(new asn1X509.GeneralName({
          otherName: new asn1X509.OtherName({
            typeId: SubjectAlternativeNameExtension.GUID,
            value: AsnConvert.serialize(new OctetString(Convert.FromHex(hex))),
          }),
        }));
      }

      // IP v4/v6
      for (const item of data.ip || []) {
        value.push(new asn1X509.GeneralName({

          iPAddress: item,
        }));
      }

      // URL
      for (const item of data.url || []) {
        value.push(new asn1X509.GeneralName({
          uniformResourceIdentifier: item,
        }));
      }

      // UPN
      for (const item of data.upn || []) {
        value.push(new asn1X509.GeneralName({
          otherName: new asn1X509.OtherName({
            typeId: SubjectAlternativeNameExtension.UPN,
            value: AsnConvert.serialize(AsnUtf8StringConverter.toASN(item))
          }),
        }));
      }

      // Registered Id
      for (const item of data.registeredId || []) {
        value.push(new asn1X509.GeneralName({
          registeredID: item,
        }));
      }

      // Other name
      for (const item of data.otherName || []) {
        value.push(new asn1X509.GeneralName({
          otherName: new asn1X509.OtherName({
            typeId: item.type,
            value: Convert.FromHex(item.value),
          }),
        }));
      }

      super(asn1X509.id_ce_subjectAltName, args[1], AsnConvert.serialize(value));
    }
  }

  onInit(asn: asn1X509.Extension) {
    super.onInit(asn);

    // value
    const value = AsnConvert.parse(asn.extnValue, asn1X509.SubjectAlternativeName);

    this.dns = value.filter(o => o.dNSName).map(o => o.dNSName || "");
    this.email = value.filter(o => o.rfc822Name).map(o => o.rfc822Name || "");
    this.ip = value.filter(o => o.iPAddress).map(o => o.iPAddress || "");
    this.url = value.filter(o => o.uniformResourceIdentifier).map(o => o.uniformResourceIdentifier || "");
    this.upn = value
      .filter(o => o.otherName?.typeId === SubjectAlternativeNameExtension.UPN)
      .map(o => o.otherName ? AsnConvert.parse(o.otherName.value, asn1X509.DirectoryString).toString() : "");
    this.guid = value
      .filter(o => o.otherName?.typeId === SubjectAlternativeNameExtension.GUID)
      .map(o => o.otherName ? AsnConvert.parse(o.otherName.value, OctetString) : new OctetString())
      .map(o => {
        const matches = /([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{12})/i.exec(Convert.ToHex(o));
        if (!matches) {
          throw new Error("Cannot parse GUID value. Value doesn't match to regular expression");
        }
        const guid = matches
          .slice(1)
          .map((o, i) => {
            if (i < 3) {
              return Convert.ToHex(new Uint8Array(Convert.FromHex(o)).reverse());
            }

            return o;
          })
          .join("-");

        return `{${guid}}`;
      });
      this.registeredId = value.filter(o => o.registeredID).map(o => o.registeredID || "");
    this.otherNames = value
      .filter(o => o.otherName && ![SubjectAlternativeNameExtension.GUID, SubjectAlternativeNameExtension.UPN].includes(o.otherName.typeId))
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      .map(o => new OtherName(o.otherName!.typeId, o.otherName!.value));
  }

  public toJSON(){
    const json: JsonSubjectAlternativeName = {};

    if (this.dns.length) {
      json.dns = [...this.dns];
    }
    if (this.email.length) {
      json.email = [...this.email];
    }
    if (this.ip.length) {
      json.ip = [...this.ip];
    }
    if (this.guid.length) {
      json.guid = [...this.guid];
    }
    if (this.upn.length) {
      json.upn = [...this.upn];
    }
    if (this.url.length) {
      json.url = [...this.url];
    }
    if (this.registeredId.length) {
      json.registeredId = [...this.registeredId];
    }
    if (this.otherNames.length) {
      json.otherName = this.otherNames.map(o => o.toJSON());
    }

    return json;
  }

}
