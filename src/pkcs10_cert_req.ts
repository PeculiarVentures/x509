import { CertificationRequest } from "@peculiar/asn1-csr";
import { AsnConvert } from "@peculiar/asn1-schema";
import { id_pkcs9_at_extensionRequest } from "@peculiar/asn1-pkcs9";
import { container } from "tsyringe";
import { Version } from "@peculiar/asn1-x509";
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

/**
 * Representation of PKCS10 Certificate Request
 */
export class Pkcs10CertificateRequest extends PemData<CertificationRequest>
  implements IPublicKeyContainer {
  public static override NAME = "PKCS#10 Certificate Request";

  protected readonly tag;

  /**
   * ToBeSigned block of CSR
   */
  #tbs?: ArrayBuffer;

  /**
   * Subject name
   */
  #subjectName?: Name;

  /**
   * Subject string
   */
  #subject?: string;

  /**
   * Signature algorithm
   */
  #signatureAlgorithm?: HashedAlgorithm;

  /**
   * Signature
   */
  #signature?: ArrayBuffer;

  /**
   * Public key
   */
  #publicKey?: PublicKey;

  /**
   * Attributes
   */
  #attributes?: Attribute[];

  /**
   * Extensions
   */
  #extensions?: Extension[];

  /**
   * Gets the subject value from the certificate as an Name
   */
  public get subjectName(): Name {
    if (!this.#subjectName) {
      this.#subjectName = new Name(this.asn.certificationRequestInfo.subject);
    }

    return this.#subjectName;
  }

  /**
   * Gets a string subject name
   */
  public get subject(): string {
    if (!this.#subject) {
      this.#subject = this.subjectName.toString();
    }

    return this.#subject;
  }

  /**
   * Gets a signature algorithm
   */
  public get signatureAlgorithm(): HashedAlgorithm {
    if (!this.#signatureAlgorithm) {
      const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
      this.#signatureAlgorithm = algProv.toWebAlgorithm(
        this.asn.signatureAlgorithm,
      ) as HashedAlgorithm;
    }

    return this.#signatureAlgorithm;
  }

  /**
   * Gets a signature
   */
  public get signature(): ArrayBuffer {
    if (!this.#signature) {
      this.#signature = this.asn.signature;
    }

    return this.#signature;
  }

  /**
   * Gets a public key of CSR
   */
  public get publicKey(): PublicKey {
    if (!this.#publicKey) {
      this.#publicKey = new PublicKey(this.asn.certificationRequestInfo.subjectPKInfo);
    }

    return this.#publicKey;
  }

  /**
   * Gets a list fo CSR attributes
   */
  public get attributes(): Attribute[] {
    if (!this.#attributes) {
      this.#attributes = this.asn.certificationRequestInfo.attributes
        .map((o) => AttributeFactory.create(AsnConvert.serialize(o)));
    }

    return this.#attributes;
  }

  /**
   * Gets a list of CSR extensions
   */
  public get extensions(): Extension[] {
    if (!this.#extensions) {
      this.#extensions = [];
      const extensions = this.getAttribute(id_pkcs9_at_extensionRequest);
      if (extensions instanceof ExtensionsAttribute) {
        this.#extensions = extensions.items;
      }
    }

    return this.#extensions;
  }

  /**
   * Gets the ToBeSigned block
   */
  private get tbs(): ArrayBuffer {
    if (!this.#tbs) {
      this.#tbs = this.asn.certificationRequestInfoRaw
        || AsnConvert.serialize(this.asn.certificationRequestInfo);
    }

    return this.#tbs;
  }

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
    const args = PemData.isAsnEncoded(param) ? [param, CertificationRequest] : [param];
    super(args[0] as any, args[1] as any);
    this.tag = PemConverter.CertificateRequestTag;
  }

  protected onInit(_asn: CertificationRequest): void {
    // Initialization is now lazy
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
    return this.attributes.filter((o) => o.type === type);
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
    return this.extensions.filter((o) => o.type === type);
  }

  /**
   * Validates CSR signature
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public async verify(crypto = cryptoProvider.get()) {
    const algorithm = {
      ...this.publicKey.algorithm, ...this.signatureAlgorithm,
    };
    const publicKey = await this.publicKey.export(algorithm, ["verify"], crypto);

    // Convert ASN.1 signature to WebCrypto format
    const signatureFormatters = container
      .resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter)
      .reverse();
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
      Version: `${Version[tbs.version]} (${tbs.version})`,
      Subject: this.subject,
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
      Algorithm: TextConverter.serializeAlgorithm(req.signatureAlgorithm),
      "": req.signature,
    });

    return obj;
  }
}
