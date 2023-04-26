import * as ocsp from "@peculiar/asn1-ocsp";
import { AsnData } from "../asn_data";
import { X509Certificate } from "../x509_cert";
import { HashedAlgorithm } from "../types";
import { AsnEncodedType, PemData } from "../pem_data";
import { AsnConvert } from "@peculiar/asn1-schema";
import { container } from "tsyringe";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";

export class CertificateID extends AsnData<ocsp.CertID> {

  /**
   * Creates an instance of a class {@link CertificateID}.
   * @param algorithm The hashing algorithm used to calculate the hash of the issuer of the certificate
   * @param issuer The certificate issuer's certificate
   * @param serialNumber Hexadecimal string of the serial number
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async create(algorithm: AlgorithmIdentifier, issuer: X509Certificate, serialNumber: string, crypto?: Crypto): Promise<CertificateID>;

  /**
   * Gets a signature algorithm
   */
  public algorithm!: HashedAlgorithm;

  /**
   * The hash of the name of the issuer of the certificate
   */
  public issuerNameHash!: ArrayBuffer;

  /**
   * The hash of the public key of the issuer of the certificate
   */
  public issuerKeyHash!: ArrayBuffer;

  /**
   * Gets a hexadecimal string of the serial number
   */
  public serialNumber!: string;

  protected onInit(asn: ocsp.CertID): void {
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    this.algorithm = algProv.toWebAlgorithm(asn.hashAlgorithm) as HashedAlgorithm;
    this.issuerNameHash = AsnConvert.serialize(asn.issuerNameHash);
    this.issuerKeyHash = AsnConvert.serialize(asn.issuerKeyHash);
    this.serialNumber = AsnConvert.toString(AsnConvert.serialize(asn.serialNumber));
  }

  /**
   * Creates a new instance
   * @param raw Encoded buffer (DER, PEM, HEX, Base64, Base64Url)
   */
  public constructor(raw: AsnEncodedType);

  /**
  * Creates a new instance from ASN.1 ocsp.CertID object
  * @param asn ASN.1 ocsp.CertID object
  */
  public constructor(asn: ocsp.CertID);
  public constructor(param: AsnEncodedType | ocsp.CertID) {
    if (PemData.isAsnEncoded(param)) {
      super(PemData.toArrayBuffer(param), ocsp.CertID);
    } else {
      super(param);
    }
  }
}