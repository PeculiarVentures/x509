import { CertificationRequest } from "@peculiar/asn1-csr";
import { AsnConvert } from "@peculiar/asn1-schema";
import { id_pkcs9_at_extensionRequest } from "@peculiar/asn1-pkcs9";
import { container } from "tsyringe";
import { Name } from "./name";
import { cryptoProvider } from "./provider";
import { HashedAlgorithm } from "./types";
import { Attribute } from "./attribute";
import { Extension } from "./extension";
import { IPublicKeyContainer, PublicKey } from "./public_key";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { AttributeFactory, ExtensionsAttribute } from "./attributes";
import { AsnEncodedType, PemData } from "./pem_data";
import { diAsnSignatureFormatter, IAsnSignatureFormatter } from "./asn_signature_formatter";
import { PemConverter } from "./pem_converter";
import { TextConverter, TextObject } from "./text_converter";
import { Version } from "@peculiar/asn1-x509";

/**
 * Representation of PKCS10 Certificate Request
 */
export class Pkcs10CertificateRequest extends PemData<CertificationRequest> implements IPublicKeyContainer {

  public static override NAME = "PKCS#10 Certificate Request";

  protected readonly tag: string;

  /**
   * ToBeSigned block of CSR
   */
  private tbs!: ArrayBuffer;

  /**
   * Gets the subject value from the certificate as an Name
   */
  public subjectName!: Name;

  /**
   * Gets a string subject name
   */
  public subject!: string;

  /**
   * Gets a signature algorithm
   */
  public signatureAlgorithm!: HashedAlgorithm;

  /**
   * Gets a signature
   */
  public signature!: ArrayBuffer;

  /**
   * Gets a public key of CSR
   */
  public publicKey!: PublicKey;

  /**
   * Gets a list fo CSR attributes
   */
  public attributes!: Attribute[];

  /**
   * Gets a list of CSR extensions
   */
  public extensions!: Extension[];

  /**
   * Creates a new instance fromDER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: AsnEncodedType);
  /**
   * Creates a new instance from ASN.1 CertificationRequest
   * @param asn ASN.1 CertificationRequest
   */
  public constructor(asn: CertificationRequest);
  public constructor(param: AsnEncodedType | CertificationRequest) {
    if (PemData.isAsnEncoded(param)) {
      super(param, CertificationRequest);
    } else {
      super(param);
    }
    this.tag = PemConverter.CertificateRequestTag;
  }

  protected onInit(asn: CertificationRequest): void {
    this.tbs = AsnConvert.serialize(asn.certificationRequestInfo);
    this.publicKey = new PublicKey(asn.certificationRequestInfo.subjectPKInfo);
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    this.signatureAlgorithm = algProv.toWebAlgorithm(asn.signatureAlgorithm) as HashedAlgorithm;
    this.signature = asn.signature;

    this.attributes = asn.certificationRequestInfo.attributes
      .map(o => AttributeFactory.create(AsnConvert.serialize(o)));
    const extensions = this.getAttribute(id_pkcs9_at_extensionRequest);
    this.extensions = [];
    if (extensions instanceof ExtensionsAttribute) {
      this.extensions = extensions.items;
    }
    this.subjectName = new Name(asn.certificationRequestInfo.subject);
    this.subject = this.subjectName.toString();
  }

  /**
   * Returns attribute of the specified type
   * @param type Attribute identifier
   * @returns Attribute or null
   */
  public getAttribute(type: string) {
    for (const attr of this.attributes) {
      if (attr.type === type) {
        return attr;
      }
    }

    return null;
  }

  /**
   * Returns a list of attributes of the specified type
   * @param type Attribute identifier
   */
  public getAttributes(type: string) {
    return this.attributes.filter(o => o.type === type);
  }

  /**
   * Returns extension of the specified type
   * @param type Extension identifier
   * @returns Extension or null
   */
  public getExtension(type: string) {
    for (const ext of this.extensions) {
      if (ext.type === type) {
        return ext;
      }
    }

    return null;
  }

  /**
   * Returns a list of extension of the specified type
   * @param type Extension identifier
   */
  public getExtensions(type: string) {
    return this.extensions.filter(o => o.type === type);
  }

  /**
   * Validates CSR signature
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async verify(crypto = cryptoProvider.get()) {
    const algorithm = { ...this.publicKey.algorithm, ...this.signatureAlgorithm };
    const publicKey = await this.publicKey.export(algorithm, ["verify"], crypto);

    // Convert ASN.1 signature to WebCrypto format
    const signatureFormatters = container.resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter).reverse();
    let signature: ArrayBuffer | null = null;
    for (const signatureFormatter of signatureFormatters) {
      signature = signatureFormatter.toWebSignature(algorithm, this.signature);
      if (signature) {
        break;
      }
    }
    if (!signature) {
      throw Error("Cannot convert WebCrypto signature value to ASN.1 format");
    }

    const ok = await crypto.subtle.verify(this.signatureAlgorithm, publicKey, signature, this.tbs);

    return ok;
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectEmpty();

    const req = AsnConvert.parse(this.rawData, CertificationRequest);

    const tbs = req.certificationRequestInfo;
    const data = new TextObject("", {
      "Version": `${Version[tbs.version]} (${tbs.version})`,
      "Subject": this.subject,
      "Subject Public Key Info": this.publicKey,
    });
    if (this.attributes.length) {
      const attrs = new TextObject("");
      for (const ext of this.attributes) {
        const attrObj = ext.toTextObject();
        attrs[attrObj[TextObject.NAME]] = attrObj;
      }
      data["Attributes"] = attrs;
    }
    obj["Data"] = data;

    obj["Signature"] = new TextObject("", {
      "Algorithm": TextConverter.serializeAlgorithm(req.signatureAlgorithm),
      "": req.signature,
    });

    return obj;
  }

}