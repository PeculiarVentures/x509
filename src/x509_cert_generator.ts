import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSource, BufferSourceConverter } from "pvtsutils";
import { container } from "tsyringe";
import { cryptoProvider } from "./provider";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { Extension } from "./extension";
import { JsonName, Name } from "./name";
import { HashedAlgorithm } from "./types";
import { X509Certificate } from "./x509_cert";
import { diAsnSignatureFormatter, IAsnSignatureFormatter } from "./asn_signature_formatter";
import { PublicKey, PublicKeyType } from "./public_key";
import { generateCertificateSerialNumber } from "./utils";

export type X509CertificateCreateParamsName = string | JsonName | Name;

/**
 * Base arguments for certificate creation
 */
export interface X509CertificateCreateParamsBase {
  /**
   * Hexadecimal serial number. If not specified, random value will be generated
   */
  serialNumber?: string;
  /**
   * Date before which certificate can't be used. Default is current date
   */
  notBefore?: Date;
  /**
   * Date after which certificate can't be used. Default is 1 year from now
   */
  notAfter?: Date;
  /**
   * List of extensions
   */
  extensions?: Extension[];
  /**
   * Signing algorithm. Default is SHA-256 with key algorithm
   */
  signingAlgorithm?: Algorithm | EcdsaParams;
}

/**
 * Common parameters for X509 Certificate generation
 */
export interface X509CertificateCreateCommonParams extends X509CertificateCreateParamsBase {
  subject?: X509CertificateCreateParamsName;
  issuer?: X509CertificateCreateParamsName;
}

/**
 * Parameters for X509 Certificate generation with private key
 */
export interface X509CertificateCreateWithKeyParams extends X509CertificateCreateCommonParams {
  publicKey: PublicKeyType;
  signingKey: CryptoKey;
}

/**
 * Parameters for X509 Certificate generation with existing signature value
 */
export interface X509CertificateCreateWithSignatureParams extends X509CertificateCreateCommonParams {
  /**
   * Signature for manually initialized certificates
   */
  signature: BufferSource;

  /**
   * Manual signing requires CryptoKey that includes signature algorithm
   */
  publicKey: PublicKeyType;
}

export type X509CertificateCreateParams = X509CertificateCreateWithKeyParams | X509CertificateCreateWithSignatureParams;


/**
 * Parameters for self-signed X509 Certificate generation
 */
export interface X509CertificateCreateSelfSignedParams extends X509CertificateCreateParamsBase {
  name?: X509CertificateCreateParamsName;
  keys: CryptoKeyPair;
}

/**
 * Generator of X509 certificates
 */
export class X509CertificateGenerator {

  /**
   * Creates a self-signed certificate
   * @param params Parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async createSelfSigned(params: X509CertificateCreateSelfSignedParams, crypto = cryptoProvider.get()) {
    if (!params.keys.privateKey) {
      throw new Error("Bad field 'keys' in 'params' argument. 'privateKey' is empty");
    }
    if (!params.keys.publicKey) {
      throw new Error("Bad field 'keys' in 'params' argument. 'publicKey' is empty");
    }

    return this.create({
      serialNumber: params.serialNumber,
      subject: params.name,
      issuer: params.name,
      notBefore: params.notBefore,
      notAfter: params.notAfter,
      publicKey: params.keys.publicKey,
      signingKey: params.keys.privateKey,
      signingAlgorithm: params.signingAlgorithm,
      extensions: params.extensions,
    }, crypto);
  }

  /**
   * Creates a certificate signed by private key
   * @param params Parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async create(params: X509CertificateCreateParams, crypto = cryptoProvider.get()) {
    let spki: BufferSource;
    if (params.publicKey instanceof PublicKey) {
      spki = params.publicKey.rawData;
    } else if ("publicKey" in params.publicKey) {
      spki = params.publicKey.publicKey.rawData;
    } else if (BufferSourceConverter.isBufferSource(params.publicKey)) {
      spki = params.publicKey;
    } else {
      spki = await crypto.subtle.exportKey("spki", params.publicKey);
    }

    const serialNumber = generateCertificateSerialNumber(params.serialNumber);
    const notBefore = params.notBefore || new Date();
    const notAfter = params.notAfter || new Date(notBefore.getTime() + 31536000000); // 1 year

    const asnX509 = new asn1X509.Certificate({
      tbsCertificate: new asn1X509.TBSCertificate({
        version: asn1X509.Version.v3,
        serialNumber,
        validity: new asn1X509.Validity({
          notBefore,
          notAfter,
        }),
        extensions: new asn1X509.Extensions(params.extensions?.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension)) || []),
        subjectPublicKeyInfo: AsnConvert.parse(spki, asn1X509.SubjectPublicKeyInfo),
      }),
    });
    if (params.subject) {
      const name = params.subject instanceof Name
        ? params.subject
        : new Name(params.subject);
      asnX509.tbsCertificate.subject = AsnConvert.parse(name.toArrayBuffer(), asn1X509.Name);
    }
    if (params.issuer) {
      const name = params.issuer instanceof Name
        ? params.issuer
        : new Name(params.issuer);
      asnX509.tbsCertificate.issuer = AsnConvert.parse(name.toArrayBuffer(), asn1X509.Name);
    }

    // Set signing algorithm
    const defaultSigningAlgorithm = {
      hash: "SHA-256",
    };
    const signatureAlgorithm = ("signingKey" in params)
      ? { ...defaultSigningAlgorithm, ...params.signingAlgorithm, ...params.signingKey.algorithm } as HashedAlgorithm
      : { ...defaultSigningAlgorithm, ...params.signingAlgorithm } as HashedAlgorithm;

    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    asnX509.tbsCertificate.signature = asnX509.signatureAlgorithm = algProv.toAsnAlgorithm(signatureAlgorithm);

    // Sign
    const tbs = AsnConvert.serialize(asnX509.tbsCertificate);
    const signatureValue = ("signingKey" in params)
      // Sign self-signed certificate with provided private key.
      ? await crypto.subtle.sign(signatureAlgorithm, params.signingKey, tbs)
      // Otherwise use given pre-signed certificate signature
      : params.signature;

    // Convert WebCrypto signature to ASN.1 format
    const signatureFormatters = container.resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter).reverse();
    let asnSignature: ArrayBuffer | null = null;
    for (const signatureFormatter of signatureFormatters) {
      asnSignature = signatureFormatter.toAsnSignature(signatureAlgorithm, signatureValue as ArrayBuffer);
      if (asnSignature) {
        break;
      }
    }
    if (!asnSignature) {
      throw Error("Cannot convert ASN.1 signature value to WebCrypto format");
    }

    asnX509.signatureValue = asnSignature;

    return new X509Certificate(AsnConvert.serialize(asnX509));
  }
}