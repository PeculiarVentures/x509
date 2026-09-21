import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { CertID } from "@peculiar/asn1-ocsp";
import { SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert, isEqual } from "pvtsutils";
import { container } from "tsyringe";
import { AsnData } from "../asn_data";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { cryptoProvider } from "../provider";
import { ParseOptions } from "../types";
import { getCertificateSerialNumber, normalizeCertificateSerialNumber } from "../utils";
import { X509Certificate } from "../x509_cert";

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
    return this.asn.issuerNameHash.buffer;
  }

  /**
   * Gets an issuer key hash
   */
  public get issuerKeyHash(): ArrayBuffer {
    return this.asn.issuerKeyHash.buffer;
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

    // RFC 6960 §4.1.1: issuerNameHash is the hash of the DER encoding of the
    // issuer's distinguished name. Use the issuer field of the target
    // certificate, not a re-serialization of the issuer certificate's subject.
    const issuerNameDer = target.issuerName.toArrayBuffer();
    const spki = AsnConvert.parse(issuer.publicKey.rawData, SubjectPublicKeyInfo);
    const issuerKeyBytes = spki.subjectPublicKey;

    const issuerNameHash = await crypto.subtle.digest(hash, issuerNameDer);
    const issuerKeyHash = await crypto.subtle.digest(hash, issuerKeyBytes);

    const serialNumber = normalizeCertificateSerialNumber(target.serialNumber);

    const asn = new CertID({
      hashAlgorithm,
      issuerNameHash: new OctetString(issuerNameHash),
      issuerKeyHash: new OctetString(issuerKeyHash),
      serialNumber,
    });

    return new OcspCertId(asn);
  }

  /**
   * Returns `true` if CertID is equal to another CertID, otherwise `false`.
   * Compares the hash algorithm OID (with absent and NULL parameters treated
   * as equal), both hashes and the serial number. The raw DER encoding is
   * intentionally not compared, so logically equal IDs with different DER
   * encodings still match.
   * @param data Any data
   */
  public override equal(data: any): data is this {
    if (data instanceof OcspCertId) {
      return (
        this.asn.hashAlgorithm.algorithm === data.asn.hashAlgorithm.algorithm &&
        isHashParametersEqual(
          this.asn.hashAlgorithm.parameters,
          data.asn.hashAlgorithm.parameters,
        ) &&
        isEqual(this.issuerNameHash, data.issuerNameHash) &&
        isEqual(this.issuerKeyHash, data.issuerKeyHash) &&
        this.serialNumber.toLowerCase() === data.serialNumber.toLowerCase()
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

/**
 * Compares hash algorithm parameters with absent and ASN.1 NULL treated as equal
 */
function isHashParametersEqual(a?: ArrayBuffer | null, b?: ArrayBuffer | null): boolean {
  const normA = normalizeHashParameters(a);
  const normB = normalizeHashParameters(b);
  if (normA === null || normB === null) {
    return normA === normB;
  }

  return isEqual(normA, normB);
}

function normalizeHashParameters(params?: ArrayBuffer | null): ArrayBuffer | null {
  if (!params || params.byteLength === 0) {
    return null;
  }
  // ASN.1 NULL is encoded as 05 00
  if (params.byteLength === 2) {
    const bytes = new Uint8Array(params);
    if (bytes[0] === 0x05 && bytes[1] === 0x00) {
      return null;
    }
  }

  return params;
}
