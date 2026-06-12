import { IAsnParseOptions } from "@peculiar/asn1-schema";

export interface HashedAlgorithm extends Algorithm {
  hash: Algorithm;
}

/**
 * Options for parsing ASN.1 encoded data. Forwards `asn1js.fromBER` resource
 * limits (`maxDepth`, `maxNodes`, `maxContentLength` via `berOptions`) so callers
 * can tune them when parsing untrusted input.
 */
export type ParseOptions = IAsnParseOptions;
