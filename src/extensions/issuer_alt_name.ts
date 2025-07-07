import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { GeneralNames, type JsonGeneralNames } from "../general_name";
import type { TextObject } from "../text_converter";

/**
 * Represents the Issuer Alternative Name certificate extension
 */
export class IssuerAlternativeNameExtension extends Extension {
	public names!: GeneralNames;

	public static override NAME = "Issuer Alternative Name";

	/**
	 * Creates a new instance from DER encoded buffer
	 * @param raw DER encoded buffer
	 */
	public constructor(raw: BufferSource);
	/**
	 * Creates a new instance
	 * @param data JSON representation of IAN
	 * @param critical Indicates where extension is critical. Default is `false`
	 */
	public constructor(data?: JsonGeneralNames, critical?: boolean);
	public constructor(...args: any[]) {
		if (BufferSourceConverter.isBufferSource(args[0])) {
			super(args[0]);
		} else {
			super(
				asn1X509.id_ce_issuerAltName,
				args[1],
				new GeneralNames(args[0] || []).rawData,
			);
		}
	}

	onInit(asn: asn1X509.Extension) {
		super.onInit(asn);

		// value
		const value = AsnConvert.parse(
			asn.extnValue,
			asn1X509.IssueAlternativeName,
		);

		this.names = new GeneralNames(value);
	}

	public override toTextObject(): TextObject {
		const obj = this.toTextObjectWithoutValue();

		const namesObj = this.names.toTextObject();
		for (const key in namesObj) {
			obj[key] = namesObj[key];
		}

		return obj;
	}
}
