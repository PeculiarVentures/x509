import * as ocsp from "@peculiar/asn1-ocsp";
import * as asn1X509 from "@peculiar/asn1-x509";
import { OctetString } from "@peculiar/asn1-schema";
import { container } from "tsyringe";
import { Convert } from "pvtsutils";
import { AsnData } from "../asn_data";
import { X509Certificate } from "../x509_cert";
import { HashedAlgorithm } from "../types";
import { AsnEncodedType, PemData } from "../pem_data";
import { AlgorithmProvider, diAlgorithmProvider } from "../algorithm";
import { cryptoProvider } from "../provider";

export class CertificateID extends AsnData<ocsp.CertID> {

  /**
   * Creates an instance of a class {@link CertificateID}.
   * @param algorithm The hashing algorithm used to calculate the hash of the issuer of the certificate
   * @param issuer The certificate issuer's certificate
   * @param serialNumber Hexadecimal string of the serial number
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async create(algorithm: AlgorithmIdentifier, issuer: X509Certificate, serialNumber: string, crypto = cryptoProvider.get()): Promise<CertificateID> {
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);

    // ONLY SHA-1 is supported
    // TODO add support for other hashing algorithms
    // TODO make better parser for algorithm identifier so there is no need to manualy set OID for algorithm
    if(algorithm != "SHA-1") {
      throw new Error("The algorithm is not supported");
    }

    // const hashAlgorithm  = new asn1X509.AlgorithmIdentifier({ algorithm: algorithm, parameters: null })
    // hashAlgorithm.algorithm = "1.3.14.3.2.26";

    const hashAlgorithm = algProv.toAsnAlgorithm({name: algorithm});

    const certId = new ocsp.CertID({
      hashAlgorithm: hashAlgorithm,
      issuerNameHash: new OctetString(await issuer.subjectName.getThumbprint(algorithm, crypto)),
      issuerKeyHash: new OctetString(await issuer.publicKey.getKeyIdentifier(crypto)),
      serialNumber: Convert.FromHex(serialNumber)
    });

    return new CertificateID(certId);
  }

  /**
   * Gets a signature algorithm
   */
  public hashAlgorithm!: HashedAlgorithm;

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
    this.hashAlgorithm = algProv.toWebAlgorithm(asn.hashAlgorithm) as HashedAlgorithm;
    this.issuerNameHash = asn.issuerNameHash.buffer;
    this.issuerKeyHash = asn.issuerKeyHash.buffer;
    this.serialNumber = Convert.ToHex(asn.serialNumber);
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