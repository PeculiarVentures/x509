import { BufferSourceConverter, Convert } from "pvtsutils";
import { cryptoProvider } from "./provider";

/**
 * Creates or normalizes a certificate serial number according to RFC 5280 requirements.
 * Ensures the serial number is positive, minimal length, and non-zero by:
 * - Using provided hex string if valid (non-empty and contains non-zero bytes)
 * - Generating 16 random bytes if input is invalid or empty
 * - Removing leading zeros while preserving at least one byte
 * - Prepending zero byte if MSB is set to ensure positive ASN.1 INTEGER
 *
 * @param input Hex string representation of desired serial number
 * @param crypto Crypto provider for random number generation
 * @returns RFC 5280 compliant serial number as ArrayBuffer
 */
export function generateCertificateSerialNumber(input: string | undefined, crypto = cryptoProvider.get()): ArrayBuffer {
  const inputView = BufferSourceConverter.toUint8Array(Convert.FromHex(input || ""));
  let serialNumber = inputView && inputView.length && inputView.some(o => o > 0)
    ? new Uint8Array(inputView)
    : undefined;
  if (!serialNumber) {
    serialNumber = crypto.getRandomValues(new Uint8Array(16));
  }

  // Remove unnecessary leading zeros
  let firstNonZero = 0;
  while (firstNonZero < serialNumber.length - 1 && serialNumber[firstNonZero] === 0) {
    firstNonZero++;
  }
  serialNumber = serialNumber.slice(firstNonZero);

  // If the first bit is 1, prepend a zero byte to ensure positive integer
  if (serialNumber[0] > 0x7F) {
    const newSerialNumber = new Uint8Array(serialNumber.length + 1);
    newSerialNumber[0] = 0x00;
    newSerialNumber.set(serialNumber, 1);
    serialNumber = newSerialNumber;
  }

  return serialNumber.buffer;
}