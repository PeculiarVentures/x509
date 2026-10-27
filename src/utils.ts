import { hex, toUint8Array } from "@peculiar/utils";
import type { BufferSourceLike } from "@peculiar/utils";
import { cryptoProvider } from "./provider";
import type { ParseOptions } from "./types";

/**
 * Hex text as `pvtsutils` 1.x read it: spaces, tabs and line breaks are ignored, an odd number of
 * digits gets a leading zero, and `0x` prefixes or other separators are rejected.
 */
export const hexOptions: hex.HexDecodeOptions = {
  allowPrefix: false,
  allowOddLength: true,
  separators: [" ", "\t", "\n", "\r"],
};

/**
 * Returns the encoded length of the first BER element in `data` (identifier, length and
 * content octets), or `undefined` for the indefinite-length form, whose end is only known
 * after parsing the content. `data` must start with a complete, parsed element header.
 */
function getElementLength(data: Uint8Array): number | undefined {
  let offset = 1;
  if ((data[0]! & 0x1f) === 0x1f) {
    // High tag number form: the tag continues while bit 8 is set
    while (data[offset++]! & 0x80);
  }
  const first = data[offset++]!;
  if (first === 0x80) {
    return undefined;
  }
  if (first < 0x80) {
    return offset + first;
  }
  let length = 0;
  for (let i = 0; i < (first & 0x7f); i++) {
    length = length * 256 + data[offset++]!;
  }
  return offset + length;
}

/**
 * Throws when `data` continues after its first ASN.1 element. `AsnConvert.parse` reads only
 * the first element, so trailing bytes would otherwise be accepted and kept in `rawData`
 * (and in thumbprints). Indefinite-length input is not checked.
 * @param data BER/DER encoded data that was parsed successfully
 */
export function assertSingleAsnElement(data: BufferSourceLike): void {
  const bytes = toUint8Array(data);
  const length = getElementLength(bytes);
  if (length !== undefined && length !== bytes.byteLength) {
    throw new Error(`Unexpected data after the ASN.1 structure: ${bytes.byteLength - length} trailing bytes`);
  }
}

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
  return toPositiveIntegerOctets(toUint8Array(hex.decode(input || "", hexOptions)));
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
export function generateCertificateSerialNumber(input: string | undefined, crypto = cryptoProvider.get()): ArrayBuffer {
  const inputView = toUint8Array(hex.decode(input || "", hexOptions));
  const serialNumber = inputView.length && inputView.some((o) => o > 0) ? inputView : crypto.getRandomValues(new Uint8Array(16));

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
  let serialNumber = toUint8Array(raw);
  if (serialNumber.length > 1 && serialNumber[0] === 0x00 && serialNumber[1] > 0x7f) {
    // Remove the leading zero that was added to make negative numbers positive
    serialNumber = serialNumber.slice(1);
  }

  return hex.encode(serialNumber);
}
