import { CertificateChoices, CertificateSet, ContentInfo, id_signedData, SignedData } from "@peculiar/asn1-cms";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
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
   * Creates a new instance from DER encoded PKCS7 buffer
   * @param raw DER encoded PKCS7 buffer
   */
  public constructor(raw: BufferSource);
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
  public constructor(param?: BufferSource | X509Certificate | X509Certificate[]) {
    super();

    if (BufferSourceConverter.isBufferSource(param)) {
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
   * Returns a DER encoded PKCS7 buffer
   */
  public export() {
    const signedData = new SignedData();

    signedData.certificates = new CertificateSet(this.map(o => new CertificateChoices({
      certificate: AsnConvert.parse(o.rawData, Certificate)
    })));

    const cms = new ContentInfo({
      contentType: id_signedData,
      content: AsnConvert.serialize(signedData),
    });

    return AsnConvert.serialize(cms);
  }

  /**
   * Import certificates from DER encoded PKCS7 buffer
   * @param data
   */
  public import(data: BufferSource) {
    const cms = AsnConvert.parse(data, ContentInfo);
    if (cms.contentType !== id_signedData) {
      throw new TypeError("Cannot parse CMS package. Incoming data is not a SignedData object.");
    }

    const signedData = AsnConvert.parse(cms.content, SignedData);
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