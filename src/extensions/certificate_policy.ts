import * as asnX509 from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSource, BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { ExtensionFactory } from "./extension_factory";
import { OidSerializer, TextObject } from "../text_converter";

/**
 * Represents the Certificate Policy extension
 */
export class CertificatePolicyExtension extends Extension {

  public static override NAME = "Certificate Policies";

  /**
   * Gets the list of certificate policies
   */
  public readonly policies: ReadonlyArray<string>;

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param policies
   * @param critical
   */
  constructor(policies: string[], critical?: boolean);
  constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);

      const asnPolicies = AsnConvert.parse(this.value, asnX509.CertificatePolicies);
      this.policies = asnPolicies.map(o => o.policyIdentifier);
    } else {
      const policies = args[0] as string[];
      const critical = args[1] ?? false;

      const value = new asnX509.CertificatePolicies(policies.map(o => (new asnX509.PolicyInformation({
        policyIdentifier: o,
      }))));

      super(asnX509.id_ce_certificatePolicies, critical, AsnConvert.serialize(value));

      this.policies = policies;
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    obj["Policy"] = this.policies.map(o => new TextObject("", {}, OidSerializer.toString(o)));

    return obj;
  }

}

ExtensionFactory.register(asnX509.id_ce_certificatePolicies, CertificatePolicyExtension);
