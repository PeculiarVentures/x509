import { BufferSourceConverter } from "pvtsutils";
import { diAsnSignatureFormatter } from "./container";

export { diAsnSignatureFormatter };

/**
 * Provides mechanism to convert ASN.1 signature value to WebCrypto and back
 *
 * To register it's implementation in global use the `container`
 * @example
 * ```
 * import { container, diAsnSignatureFormatter } from "./container";
 *
 * container.registerSingleton(diAsnSignatureFormatter, AsnDefaultSignatureFormatter);
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
