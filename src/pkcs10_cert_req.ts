import { CertificationRequest } from "@peculiar/asn1-csr";
import { AsnConvert } from "@peculiar/asn1-schema";
import { id_pkcs9_at_extensionRequest } from "@peculiar/asn1-pkcs9";
import { Extensions } from "@peculiar/asn1-x509";
import { Name } from "./name";
import { cryptoProvider } from "./provider";
import { HashedAlgorithm } from "./types";
import { BufferSourceConverter } from "pvtsutils";
import { AsnData } from "./asn_data";
import { Attribute } from "./attribute";
import { Extension } from "./extension";
import { PublicKey } from "./public_key";
import { container } from "tsyringe";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";

/**
 * Representation of PKCS10 Certificate Request
 */
export class Pkcs10CertificateRequest extends AsnData<CertificationRequest> {

  /**
   * ToBeSigned block of CSR
   */
  private tbs!: ArrayBuffer;

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
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance from ASN.1 CertificationRequest
   * @param asn ASN.1 CertificationRequest
   */
  public constructor(asn: CertificationRequest);
  public constructor(param: BufferSource | CertificationRequest) {
    if (BufferSourceConverter.isBufferSource(param)) {
      super(param, CertificationRequest);
    } else {
      super(param);
    }
  }

  protected onInit(asn: CertificationRequest): void {
    this.tbs = AsnConvert.serialize(asn.certificationRequestInfo);
    this.publicKey = new PublicKey(asn.certificationRequestInfo.subjectPKInfo);
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    this.signatureAlgorithm = algProv.toWebAlgorithm(asn.signatureAlgorithm) as HashedAlgorithm;
    this.signature = asn.signature;

    this.attributes = asn.certificationRequestInfo.attributes
      .map(o => new Attribute(AsnConvert.serialize(o)));
    const extensions = this.getAttribute(id_pkcs9_at_extensionRequest)?.values[0];
    this.extensions = [];
    if (extensions) {
      this.extensions = AsnConvert.parse(extensions, Extensions)
        .map(o => new Extension(AsnConvert.serialize(o)));
    }
    this.subject = new Name(asn.certificationRequestInfo.subject).toString();
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
    const ok = await crypto.subtle.verify(this.signatureAlgorithm, publicKey, this.signature, this.tbs);
    return ok;
  }

}