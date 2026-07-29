import { BufferSourceConverter } from "pvtsutils";

/**
 * Dependency injection identifier for `IAsnSignatureFormatter` interface
 */
export const diAsnSignatureFormatter = "crypto.signatureFormatter";

/**
 * Provides mechanism to convert ASN.1 signature value to WebCrypto and back
 *
 * To register an implementation, add it to the exported `container`
 * @example
 * ```
 * import { container, diAsnSignatureFormatter } from "@peculiar/x509";
 * import { AsnDefaultSignatureFormatter } from "@peculiar/x509";
 *
 * container.registerMany(diAsnSignatureFormatter, {
 *   useValue: new AsnDefaultSignatureFormatter(),
 * });
 * ```
 */
export interface IAsnSignatureFormatter {
  /**
   * Converts ASN.1 signature to WebCrypto format
   * @param algorithm Key and signing algorithm
   * @param signature ASN.1 signature value in DER format
   */
  toAsnSignature(algorithm: Algorithm, signature: BufferSource): ArrayBuffer | null;
  /**
   * Converts WebCrypto signature to ASN.1 DER encoded signature value
   * @param algorithm
   * @param signature
   */
  toWebSignature(algorithm: Algorithm, signature: BufferSource): ArrayBuffer | null;
}

export class AsnDefaultSignatureFormatter implements IAsnSignatureFormatter {
  toAsnSignature(algorithm: Algorithm, signature: BufferSource): ArrayBuffer | null {
    return BufferSourceConverter.toArrayBuffer(signature);
  }

  toWebSignature(algorithm: Algorithm, signature: BufferSource): ArrayBuffer | null {
    return BufferSourceConverter.toArrayBuffer(signature);
  }
}
