import { BufferSourceConverter, Convert } from "pvtsutils";
import { cryptoProvider } from "./provider";
import { ParseOptions } from "./types";

/**
 * Parse options for DER this library produced itself.
 *
 * Objects here keep their value as DER and re-parse it to derive the ASN.1 view, so
 * creating one involves several serialize/parse round-trips of bytes built from
 * structures already in memory. The `asn1js` limits exist to bound untrusted input;
 * applying them to those round-trips protects nothing and caps what a caller may build
 * (10000 nodes is roughly 2500 RDNs). So limits apply to DER the caller handed us -- the
 * `raw` / `AsnEncodedType` constructors, and a raw `publicKey` -- and not to ours.
 *
 * Note that an object built this way stores these options, so its lazy accessors are
 * unlimited too, including for foreign DER embedded in it. Bound such input on the way in
 * with {@link ExtensionFactory.create} or a concrete extension class, which parse the
 * value; `new Extension(raw)` only parses the wrapper.
 */
export const selfProducedParseOptions: ParseOptions = {
  berOptions: {
    maxDepth: Infinity,
    maxNodes: Infinity,
    maxContentLength: Infinity,
  },
};

/**
 * Encodes serial number bytes as the content octets of a positive ASN.1 INTEGER by:
 * - Removing leading zeros while preserving at least one byte
 * - Prepending zero byte if MSB is set to ensure positive ASN.1 INTEGER
 *
 * @param input Serial number bytes
 * @returns DER INTEGER content octets
 */
function toPositiveIntegerOctets(input: Uint8Array): ArrayBuffer {
  // Remove unnecessary leading zeros
  let firstNonZero = 0;
  while (firstNonZero < input.length - 1 && input[firstNonZero] === 0) {
    firstNonZero++;
  }
  let serialNumber = input.slice(firstNonZero);

  if (!serialNumber.length) {
    serialNumber = new Uint8Array([0x00]);
  }

  // If the first bit is 1, prepend a zero byte to ensure positive integer
  if (serialNumber[0] > 0x7f) {
    const newSerialNumber = new Uint8Array(serialNumber.length + 1);
    newSerialNumber[0] = 0x00;
    newSerialNumber.set(serialNumber, 1);
    serialNumber = newSerialNumber;
  }

  return serialNumber.buffer;
}

/**
 * Normalizes a certificate serial number without ever replacing the given value. The
 * serial number is encoded as a positive, minimal length ASN.1 INTEGER. Empty and
 * all-zero input is normalized to a single zero byte.
 *
 * @param input Hex string representation of the serial number
 * @returns Serial number as ArrayBuffer
 */
export function normalizeCertificateSerialNumber(input: string | undefined): ArrayBuffer {
  return toPositiveIntegerOctets(BufferSourceConverter.toUint8Array(Convert.FromHex(input || "")));
}

/**
 * Creates or normalizes a certificate serial number according to RFC 5280 requirements.
 * Ensures the serial number is positive, minimal length, and non-zero by:
 * - Using provided hex string if valid (non-empty and contains non-zero bytes)
 * - Generating 16 random bytes if input is invalid or empty
 * - Normalizing the result with {@link normalizeCertificateSerialNumber}
 *
 * Use {@link normalizeCertificateSerialNumber} where a caller supplied serial number
 * must never be replaced, such as for CRL entries.
 *
 * @param input Hex string representation of desired serial number
 * @param crypto Crypto provider for random number generation
 * @returns RFC 5280 compliant serial number as ArrayBuffer
 */
export function generateCertificateSerialNumber(
  input: string | undefined,
  crypto = cryptoProvider.get(),
): ArrayBuffer {
  const inputView = BufferSourceConverter.toUint8Array(Convert.FromHex(input || ""));
  const serialNumber =
    inputView.length && inputView.some((o) => o > 0)
      ? inputView
      : crypto.getRandomValues(new Uint8Array(16));

  return toPositiveIntegerOctets(serialNumber);
}

/**
 * Reads a certificate serial number from DER INTEGER content octets and returns
 * it as a hexadecimal string. Strips the leading sign-pad byte (`0x00`) that is
 * prepended to keep a high-bit-set value a positive INTEGER, so the returned
 * string matches the original (unpadded) serial number.
 *
 * @param raw DER INTEGER content octets (e.g. `tbsCertificate.serialNumber` or
 *   a CRL entry's `userCertificate`)
 * @returns Hexadecimal string of the serial number, without sign padding
 */
export function getCertificateSerialNumber(raw: BufferSource): string {
  let serialNumber = BufferSourceConverter.toUint8Array(raw);
  if (serialNumber.length > 1 && serialNumber[0] === 0x00 && serialNumber[1] > 0x7f) {
    // Remove the leading zero that was added to make negative numbers positive
    serialNumber = serialNumber.slice(1);
  }

  return Convert.ToHex(serialNumber);
}
