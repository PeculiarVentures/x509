import "reflect-metadata";

export * from "./extensions";
export * from "./attributes";
export * from "./asn_data";
export * from "./asn_signature_formatter";
export * from "./algorithm";
export * from "./rsa_algorithm";
export * from "./ec_algorithm";
export * from "./ec_signature_formatter";
export * from "./ed_algorithm";
export * from "./asn_data";
export * from "./attribute";
export * from "./extension";
export * from "./name";
export * from "./pem_converter";
export * from "./pkcs10_cert_req";
export * from "./pkcs10_cert_req_generator";
export * from "./provider";
export * from "./public_key";
export * from "./types";
export * from "./x509_cert";
export * from "./x509_chain_builder";
export * from "./x509_cert_generator";
export * from "./x509_certs";
export * from "./x509_crl";
export * from "./x509_crl_entry";
export * from "./x509_crl_generator";
export * from "./x509_chain_validator";
export * from "./certificate_storage_handler";
export * from "./x509_certificate_tree";
export * from "./text_converter";
export * from "./general_name";

import * as asnX509 from "@peculiar/asn1-x509";
import * as asnPkcs9 from "@peculiar/asn1-pkcs9";
import * as attributes from "./attributes";
import * as extensions from "./extensions";
import { container } from "tsyringe";
import { AsnDefaultSignatureFormatter, diAsnSignatureFormatter } from "./asn_signature_formatter";
import { AsnEcSignatureFormatter } from "./ec_signature_formatter";
export * as rules from "./rules";

// Register x509 extensions
extensions.ExtensionFactory.register(asnX509.id_ce_basicConstraints, extensions.BasicConstraintsExtension);
extensions.ExtensionFactory.register(asnX509.id_ce_extKeyUsage, extensions.ExtendedKeyUsageExtension);
extensions.ExtensionFactory.register(asnX509.id_ce_keyUsage, extensions.KeyUsagesExtension);
extensions.ExtensionFactory.register(asnX509.id_ce_subjectKeyIdentifier, extensions.SubjectKeyIdentifierExtension);
extensions.ExtensionFactory.register(asnX509.id_ce_authorityKeyIdentifier, extensions.AuthorityKeyIdentifierExtension);
extensions.ExtensionFactory.register(asnX509.id_ce_subjectAltName, extensions.SubjectAlternativeNameExtension);

// Register x509 attributes
attributes.AttributeFactory.register(asnPkcs9.id_pkcs9_at_challengePassword, attributes.ChallengePasswordAttribute);
attributes.AttributeFactory.register(asnPkcs9.id_pkcs9_at_extensionRequest, attributes.ExtensionsAttribute);

// Register signature formatters
container.registerSingleton(diAsnSignatureFormatter, AsnDefaultSignatureFormatter);
container.registerSingleton(diAsnSignatureFormatter, AsnEcSignatureFormatter);

// Register EC named curves sizes
AsnEcSignatureFormatter.namedCurveSize.set("P-256", 32);
AsnEcSignatureFormatter.namedCurveSize.set("K-256", 32);
AsnEcSignatureFormatter.namedCurveSize.set("P-384", 48);
AsnEcSignatureFormatter.namedCurveSize.set("P-521", 66);
