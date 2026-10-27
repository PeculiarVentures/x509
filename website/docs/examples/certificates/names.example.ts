import "reflect-metadata";
import * as x509 from "@peculiar/x509";

// Distinguished names in the RFC 4514 string form
const name = new x509.Name("CN=John Smith, OU=Sales+OU=Marketing, O=Example\\, Inc., C=US");

console.log("string:", name.toString());
console.log("CN:", name.getField("CN"));
console.log("OU:", name.getField("OU"));
console.log("O:", name.getField("O"));

// The same name as JSON: one object per RDN, values grouped by attribute
const json = name.toJSON();
console.log("JSON:", json);
console.log("from JSON:", new x509.Name(json).toString());

// Attributes without a short name use their OID; values starting with # are hex-encoded DER
const custom = new x509.Name("CN=Device 42, 2.5.4.5=#13053132333435");
console.log("serialNumber attribute:", custom.toJSON());

// Register short names for other attributes
const extra = new x509.Name("CN=Device 42, SERIAL=12345", { SERIAL: "2.5.4.5" });
console.log("with a short name:", extra.toString(), extra.getField("SERIAL"));

// DER bytes, as stored in certificates, and back
const der = name.toArrayBuffer();
console.log("DER length:", der.byteLength);
console.log("from DER:", new x509.Name(der).toString());
