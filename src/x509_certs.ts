import * as asn1Cms from "@peculiar/asn1-cms";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import { Convert } from "pvtsutils";
import { PemConverter } from "./pem_converter";
import { AsnEncodedType, AsnExportType, PemData } from "./pem_data";
import { X509Certificate } from "./x509_cert";

/**
 * X509 Certificate collection
 */
export class X509Certificates extends Array<X509Certificate> {

  /**
   * Creates a new instance
   */
  public constructor();
  /**
   * Creates a new instance from encoded PKCS7 buffer
   * @param raw Encoded PKCS7 buffer. Supported formats are DER, PEM, HEX, Base64, or Base64Url
   */
  public constructor(raw: AsnEncodedType);
  /**
   * Creates a new instance form X509 certificate
   * @param cert X509 certificate
   */
  public constructor(cert: X509Certificate);
  /**
   * Creates a new instance from a list of x509 certificates
   * @param certs List of x509 certificates
   */
  public constructor(certs: X509Certificate[]);
  public constructor(param?: AsnEncodedType | X509Certificate | X509Certificate[]) {
    super();

    if (PemData.isAsnEncoded(param)) {
      this.import(param);
    } else if (param instanceof X509Certificate) {
      this.push(param);
    } else if (Array.isArray(param)) {
      for (const item of param) {
        this.push(item);
      }
    }
  }

  /**
   * Returns encoded object in DER format
   * @param format raw
   */
  public export(format: "raw"): ArrayBuffer;
  /**
   * Returns encoded object in selected format
   * @param format `hex`, `base64`, `base64url`, `pem`. Default is `pem`
   */
  public export(format?: AsnExportType): string;
  public export(format: AsnExportType | "raw" = "pem") {
    const signedData = new asn1Cms.SignedData();

    signedData.certificates = new asn1Cms.CertificateSet(this.map(o => new asn1Cms.CertificateChoices({
      certificate: AsnConvert.parse(o.rawData, Certificate)
    })));

    const cms = new asn1Cms.ContentInfo({
      contentType: asn1Cms.id_signedData,
      content: AsnConvert.serialize(signedData),
    });

    const raw = AsnConvert.serialize(cms);
    switch (format) {
      case "raw":
        return raw;
      case "pem":
        return PemConverter.encode(raw, "CMS");
      case "hex":
        return Convert.ToHex(raw);
      case "base64":
        return Convert.ToBase64(raw);
      case "base64url":
        return Convert.ToBase64Url(raw);
      default:
        throw TypeError("Argument 'format' is unsupported value");
    }
  }

  /**
   * Import certificates from encoded PKCS7 data. Supported formats are HEX, DER, Base64, Base64Url, PEM
   * @param data
   */
  public import(data: AsnEncodedType) {
    const raw = PemData.toArrayBuffer(data);
    const cms = AsnConvert.parse(raw, asn1Cms.ContentInfo);
    if (cms.contentType !== asn1Cms.id_signedData) {
      throw new TypeError("Cannot parse CMS package. Incoming data is not a SignedData object.");
    }

    const signedData = AsnConvert.parse(cms.content, asn1Cms.SignedData);
    this.clear();

    for (const item of signedData.certificates || []) {
      if (item.certificate) {
        this.push(new X509Certificate(item.certificate));
      }
    }
  }

  /**
   * Removes all items from collection
   */
  public clear() {
    while (this.pop()) {
      // nothing;
    }
  }

}