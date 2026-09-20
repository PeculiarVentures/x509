import { AsnConvert } from "@peculiar/asn1-schema";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert, isEqual } from "pvtsutils";
import { container } from "tsyringe";
import { AsnData } from "../asn_data";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { cryptoProvider } from "../provider";
import { ParseOptions } from "../types";
import { getCertificateSerialNumber, normalizeCertificateSerialNumber } from "../utils";
import { X509Certificate } from "../x509_cert";
import { CertID } from "./asn";

export type OcspHashAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

/**
 * Representation of OCSP CertID
 */
export class OcspCertId extends AsnData<CertID> {
  public static override NAME = "OCSP CertID";

  #hashAlgorithm?: Algorithm;
  #serialNumber?: string;

  /**
   * Gets a hash algorithm
   */
  public get hashAlgorithm(): Algorithm {
    if (!this.#hashAlgorithm) {
      const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
      this.#hashAlgorithm = algProv.toWebAlgorithm(this.asn.hashAlgorithm);
    }

    return this.#hashAlgorithm;
  }

  /**
   * Gets an issuer name hash
   */
  public get issuerNameHash(): ArrayBuffer {
    return this.asn.issuerNameHash;
  }

  /**
   * Gets an issuer key hash
   */
  public get issuerKeyHash(): ArrayBuffer {
    return this.asn.issuerKeyHash;
  }

  /**
   * Gets a hexadecimal string of the serial number
   */
  public get serialNumber(): string {
    if (!this.#serialNumber) {
      this.#serialNumber = getCertificateSerialNumber(this.asn.serialNumber);
    }

    return this.#serialNumber;
  }

  /**
   * Creates a new instance from ASN.1 CertID object
   * @param asn ASN.1 CertID object
   * @param options Optional ASN.1 parse options
   */
  public constructor(asn: CertID, options?: ParseOptions);
  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   * @param options Optional ASN.1 parse options
   */
  public constructor(raw: BufferSource, options?: ParseOptions);
  public constructor(param: BufferSource | CertID, options?: ParseOptions) {
    const args = BufferSourceConverter.isBufferSource(param)
      ? [param, CertID, options]
      : [param, options];
    super(args[0] as any, args[1] as any, args[2] as any);
  }

  protected onInit(_asn: CertID): void {
    // Initialization is now lazy
  }

  /**
   * Creates a CertID for a target certificate issued by an issuer certificate
   * @param issuer Issuer certificate
   * @param target Target certificate
   * @param hash Hash algorithm. Default is SHA-256
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async create(
    issuer: X509Certificate,
    target: X509Certificate,
    hash: OcspHashAlgorithm = "SHA-256",
    crypto = cryptoProvider.get(),
  ): Promise<OcspCertId> {
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    const hashAlgorithm = algProv.toAsnAlgorithm({ name: hash });

    const issuerNameDer = issuer.subjectName.toArrayBuffer();
    const spki = AsnConvert.parse(issuer.publicKey.rawData, SubjectPublicKeyInfo);
    const issuerKeyBytes = spki.subjectPublicKey;

    const issuerNameHash = await crypto.subtle.digest(hash, issuerNameDer);
    const issuerKeyHash = await crypto.subtle.digest(hash, issuerKeyBytes);

    const serialNumber = normalizeCertificateSerialNumber(target.serialNumber);

    const asn = new CertID({
      hashAlgorithm,
      issuerNameHash,
      issuerKeyHash,
      serialNumber,
    });

    return new OcspCertId(asn);
  }

  /**
   * Returns `true` if CertID is equal to another CertID, otherwise `false`
   * @param data Any data
   */
  public override equal(data: any): data is this {
    if (data instanceof OcspCertId) {
      return (
        isEqual(this.issuerNameHash, data.issuerNameHash) &&
        isEqual(this.issuerKeyHash, data.issuerKeyHash) &&
        this.serialNumber.toLowerCase() === data.serialNumber.toLowerCase() &&
        isEqual(this.rawData, data.rawData)
      );
    }

    return false;
  }

  /**
   * Returns serial number and hashes for debugging
   */
  public toJSON(): {
    hashAlgorithm: string;
    issuerNameHash: string;
    issuerKeyHash: string;
    serialNumber: string;
  } {
    const name = "name" in this.hashAlgorithm ? (this.hashAlgorithm as Algorithm).name : "unknown";

    return {
      hashAlgorithm: name,
      issuerNameHash: Convert.ToHex(this.issuerNameHash),
      issuerKeyHash: Convert.ToHex(this.issuerKeyHash),
      serialNumber: this.serialNumber,
    };
  }
}
