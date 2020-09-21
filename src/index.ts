import "reflect-metadata";

export * from "./extensions";
export * from "./attributes";
export * from "./algorithm";
export * from "./rsa_algorithm";
export * from "./ec_algorithm";
export * from "./asn_data";
export * from "./attribute";
export * from "./extension";
export * from "./name";
export * from "./pkcs10_cert_req";
export * from "./pkcs10_cert_req_generator";
export * from "./provider";
export * from "./public_key";
export * from "./types";
export * from "./x509_cert";
export * from "./x509_chain_builder";
export * from "./x509_cert_generator";
export * from "./x509_certs";

import * as asnX509 from "@peculiar/asn1-x509";
import * as asnPkcs9 from "@peculiar/asn1-pkcs9";
import * as attributes from "./attributes";
import * as extensions from "./extensions";

// Register x509 extensions
extensions.ExtensionFactory.register(asnX509.id_ce_basicConstraints, extensions.BasicConstraintsExtension);
extensions.ExtensionFactory.register(asnX509.id_ce_extKeyUsage, extensions.ExtendedKeyUsageExtension);
extensions.ExtensionFactory.register(asnX509.id_ce_keyUsage, extensions.KeyUsagesExtension);
extensions.ExtensionFactory.register(asnX509.id_ce_subjectKeyIdentifier, extensions.SubjectKeyIdentifierExtension);
extensions.ExtensionFactory.register(asnX509.id_ce_authorityKeyIdentifier, extensions.AuthorityKeyIdentifierExtension);

// Register x509 attributes
attributes.AttributeFactory.register(asnPkcs9.id_pkcs9_at_challengePassword, attributes.ChallengePasswordAttribute);
attributes.AttributeFactory.register(asnPkcs9.id_pkcs9_at_extensionRequest, attributes.ExtensionsAttribute);
