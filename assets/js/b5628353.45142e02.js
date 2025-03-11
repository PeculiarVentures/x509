"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[5303],{994:(e,r,n)=>{n.r(r),n.d(r,{assets:()=>c,contentTitle:()=>t,default:()=>x,frontMatter:()=>d,metadata:()=>s,toc:()=>a});const s=JSON.parse('{"id":"api/classes/X509Crl","title":"X509Crl","description":"Representation of X.509 Certificate Revocation List (CRL)","source":"@site/docs/api/classes/X509Crl.md","sourceDirName":"api/classes","slug":"/api/classes/X509Crl","permalink":"/x509/docs/api/classes/X509Crl","draft":false,"unlisted":false,"tags":[],"version":"current","frontMatter":{},"sidebar":"docs","previous":{"title":"X509ChainBuilder","permalink":"/x509/docs/api/classes/X509ChainBuilder"},"next":{"title":"X509CrlEntry","permalink":"/x509/docs/api/classes/X509CrlEntry"}}');var i=n(4848),l=n(8453);const d={},t="X509Crl",c={},a=[{value:"Extends",id:"extends",level:2},{value:"Constructors",id:"constructors",level:2},{value:"new X509Crl()",id:"new-x509crl",level:3},{value:"Parameters",id:"parameters",level:4},{value:"asn",id:"asn",level:5},{value:"Returns",id:"returns",level:4},{value:"Overrides",id:"overrides",level:4},{value:"new X509Crl()",id:"new-x509crl-1",level:3},{value:"Parameters",id:"parameters-1",level:4},{value:"raw",id:"raw",level:5},{value:"Returns",id:"returns-1",level:4},{value:"Overrides",id:"overrides-1",level:4},{value:"Properties",id:"properties",level:2},{value:"entries",id:"entries",level:3},{value:"extensions",id:"extensions",level:3},{value:"issuer",id:"issuer",level:3},{value:"issuerName",id:"issuername",level:3},{value:"nextUpdate?",id:"nextupdate",level:3},{value:"rawData",id:"rawdata",level:3},{value:"Inherited from",id:"inherited-from",level:4},{value:"signature",id:"signature",level:3},{value:"signatureAlgorithm",id:"signaturealgorithm",level:3},{value:"tag",id:"tag",level:3},{value:"Overrides",id:"overrides-2",level:4},{value:"thisUpdate",id:"thisupdate",level:3},{value:"version?",id:"version",level:3},{value:"NAME",id:"name",level:3},{value:"Inherited from",id:"inherited-from-1",level:4},{value:"Methods",id:"methods",level:2},{value:"equal()",id:"equal",level:3},{value:"Parameters",id:"parameters-2",level:4},{value:"data",id:"data",level:5},{value:"Returns",id:"returns-2",level:4},{value:"Inherited from",id:"inherited-from-2",level:4},{value:"findRevoked()",id:"findrevoked",level:3},{value:"Parameters",id:"parameters-3",level:4},{value:"certOrSerialNumber",id:"certorserialnumber",level:5},{value:"Returns",id:"returns-3",level:4},{value:"getExtension()",id:"getextension",level:3},{value:"Call Signature",id:"call-signature",level:4},{value:"Type Parameters",id:"type-parameters",level:5},{value:"Parameters",id:"parameters-4",level:5},{value:"type",id:"type",level:6},{value:"Returns",id:"returns-4",level:5},{value:"Call Signature",id:"call-signature-1",level:4},{value:"Type Parameters",id:"type-parameters-1",level:5},{value:"Parameters",id:"parameters-5",level:5},{value:"type",id:"type-1",level:6},{value:"Returns",id:"returns-5",level:5},{value:"getExtensions()",id:"getextensions",level:3},{value:"Param",id:"param",level:4},{value:"Call Signature",id:"call-signature-2",level:4},{value:"Type Parameters",id:"type-parameters-2",level:5},{value:"Parameters",id:"parameters-6",level:5},{value:"type",id:"type-2",level:6},{value:"Returns",id:"returns-6",level:5},{value:"Param",id:"param-1",level:5},{value:"Call Signature",id:"call-signature-3",level:4},{value:"Type Parameters",id:"type-parameters-3",level:5},{value:"Parameters",id:"parameters-7",level:5},{value:"type",id:"type-3",level:6},{value:"Returns",id:"returns-7",level:5},{value:"Param",id:"param-2",level:5},{value:"getTextName()",id:"gettextname",level:3},{value:"Returns",id:"returns-8",level:4},{value:"Inherited from",id:"inherited-from-3",level:4},{value:"getThumbprint()",id:"getthumbprint",level:3},{value:"Call Signature",id:"call-signature-4",level:4},{value:"Parameters",id:"parameters-8",level:5},{value:"crypto?",id:"crypto",level:6},{value:"Returns",id:"returns-9",level:5},{value:"Call Signature",id:"call-signature-5",level:4},{value:"Parameters",id:"parameters-9",level:5},{value:"algorithm",id:"algorithm",level:6},{value:"crypto?",id:"crypto-1",level:6},{value:"Returns",id:"returns-10",level:5},{value:"onInit()",id:"oninit",level:3},{value:"Parameters",id:"parameters-10",level:4},{value:"asn",id:"asn-1",level:5},{value:"Returns",id:"returns-11",level:4},{value:"Overrides",id:"overrides-3",level:4},{value:"toString()",id:"tostring",level:3},{value:"Call Signature",id:"call-signature-6",level:4},{value:"Returns",id:"returns-12",level:5},{value:"Inherited from",id:"inherited-from-4",level:5},{value:"Call Signature",id:"call-signature-7",level:4},{value:"Parameters",id:"parameters-11",level:5},{value:"format",id:"format",level:6},{value:"Returns",id:"returns-13",level:5},{value:"Inherited from",id:"inherited-from-5",level:5},{value:"toTextObject()",id:"totextobject",level:3},{value:"Returns",id:"returns-14",level:4},{value:"Inherited from",id:"inherited-from-6",level:4},{value:"toTextObjectEmpty()",id:"totextobjectempty",level:3},{value:"Parameters",id:"parameters-12",level:4},{value:"value?",id:"value",level:5},{value:"Returns",id:"returns-15",level:4},{value:"Inherited from",id:"inherited-from-7",level:4},{value:"verify()",id:"verify",level:3},{value:"Parameters",id:"parameters-13",level:4},{value:"params",id:"params",level:5},{value:"crypto",id:"crypto-2",level:5},{value:"Returns",id:"returns-16",level:4},{value:"isAsnEncoded()",id:"isasnencoded",level:3},{value:"Parameters",id:"parameters-14",level:4},{value:"data",id:"data-1",level:5},{value:"Returns",id:"returns-17",level:4},{value:"Inherited from",id:"inherited-from-8",level:4},{value:"toArrayBuffer()",id:"toarraybuffer",level:3},{value:"Parameters",id:"parameters-15",level:4},{value:"raw",id:"raw-1",level:5},{value:"Returns",id:"returns-18",level:4},{value:"Inherited from",id:"inherited-from-9",level:4}];function h(e){const r={a:"a",blockquote:"blockquote",code:"code",em:"em",h1:"h1",h2:"h2",h3:"h3",h4:"h4",h5:"h5",h6:"h6",header:"header",hr:"hr",li:"li",p:"p",strong:"strong",ul:"ul",...(0,l.R)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(r.header,{children:(0,i.jsx)(r.h1,{id:"x509crl",children:"X509Crl"})}),"\n",(0,i.jsx)(r.p,{children:"Representation of X.509 Certificate Revocation List (CRL)"}),"\n",(0,i.jsx)(r.h2,{id:"extends",children:"Extends"}),"\n",(0,i.jsxs)(r.ul,{children:["\n",(0,i.jsxs)(r.li,{children:[(0,i.jsx)(r.code,{children:"PemData"}),"<",(0,i.jsx)(r.code,{children:"CertificateList"}),">"]}),"\n"]}),"\n",(0,i.jsx)(r.h2,{id:"constructors",children:"Constructors"}),"\n",(0,i.jsx)(r.h3,{id:"new-x509crl",children:"new X509Crl()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"new X509Crl"}),"(",(0,i.jsx)(r.code,{children:"asn"}),"): ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/X509Crl",children:(0,i.jsx)(r.code,{children:"X509Crl"})})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Creates a new instance from ASN.1 CertificateList object"}),"\n",(0,i.jsx)(r.h4,{id:"parameters",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"asn",children:"asn"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"CertificateList"})}),"\n",(0,i.jsx)(r.p,{children:"ASN.1 CertificateList object"}),"\n",(0,i.jsx)(r.h4,{id:"returns",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/X509Crl",children:(0,i.jsx)(r.code,{children:"X509Crl"})})}),"\n",(0,i.jsx)(r.h4,{id:"overrides",children:"Overrides"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData<CertificateList>.constructor"})}),"\n",(0,i.jsx)(r.h3,{id:"new-x509crl-1",children:"new X509Crl()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"new X509Crl"}),"(",(0,i.jsx)(r.code,{children:"raw"}),"): ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/X509Crl",children:(0,i.jsx)(r.code,{children:"X509Crl"})})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Creates a new instance"}),"\n",(0,i.jsx)(r.h4,{id:"parameters-1",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"raw",children:"raw"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"AsnEncodedType"})}),"\n",(0,i.jsx)(r.p,{children:"Encoded buffer (DER, PEM, HEX, Base64, Base64Url)"}),"\n",(0,i.jsx)(r.h4,{id:"returns-1",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/X509Crl",children:(0,i.jsx)(r.code,{children:"X509Crl"})})}),"\n",(0,i.jsx)(r.h4,{id:"overrides-1",children:"Overrides"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData<CertificateList>.constructor"})}),"\n",(0,i.jsx)(r.h2,{id:"properties",children:"Properties"}),"\n",(0,i.jsx)(r.h3,{id:"entries",children:"entries"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"entries"}),": readonly ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/X509CrlEntry",children:(0,i.jsx)(r.code,{children:"X509CrlEntry"})}),"[]"]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets a crlEntries from the CRL"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"extensions",children:"extensions"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"extensions"}),": ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,i.jsx)(r.code,{children:"Extension"})}),"[]"]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gts a list of crl extensions"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"issuer",children:"issuer"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"issuer"}),": ",(0,i.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets a string issuer name"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"issuername",children:"issuerName"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"issuerName"}),": ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/Name",children:(0,i.jsx)(r.code,{children:"Name"})})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets the issuer value from the crl as an Name"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"nextupdate",children:"nextUpdate?"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"optional"})," ",(0,i.jsx)(r.strong,{children:"nextUpdate"}),": ",(0,i.jsx)(r.code,{children:"Date"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets a nextUpdate date from the CRL"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"rawdata",children:"rawData"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"readonly"})," ",(0,i.jsx)(r.strong,{children:"rawData"}),": ",(0,i.jsx)(r.code,{children:"ArrayBuffer"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets a DER encoded buffer"}),"\n",(0,i.jsx)(r.h4,{id:"inherited-from",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.rawData"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"signature",children:"signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"signature"}),": ",(0,i.jsx)(r.code,{children:"ArrayBuffer"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets a signature"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"signaturealgorithm",children:"signatureAlgorithm"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"signatureAlgorithm"}),": ",(0,i.jsx)(r.a,{href:"/x509/docs/api/interfaces/HashedAlgorithm",children:(0,i.jsx)(r.code,{children:"HashedAlgorithm"})})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets a signature algorithm"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"tag",children:"tag"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"protected"})," ",(0,i.jsx)(r.code,{children:"readonly"})," ",(0,i.jsx)(r.strong,{children:"tag"}),": ",(0,i.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"PEM tag"}),"\n",(0,i.jsx)(r.h4,{id:"overrides-2",children:"Overrides"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.tag"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"thisupdate",children:"thisUpdate"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"thisUpdate"}),": ",(0,i.jsx)(r.code,{children:"Date"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets a thisUpdate date from the CRL"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"version",children:"version?"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"optional"})," ",(0,i.jsx)(r.strong,{children:"version"}),": ",(0,i.jsx)(r.code,{children:"Version"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets a version"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"name",children:"NAME"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"NAME"}),": ",(0,i.jsx)(r.code,{children:"string"})," = ",(0,i.jsx)(r.code,{children:'"ASN"'})]}),"\n"]}),"\n",(0,i.jsx)(r.h4,{id:"inherited-from-1",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.NAME"})}),"\n",(0,i.jsx)(r.h2,{id:"methods",children:"Methods"}),"\n",(0,i.jsx)(r.h3,{id:"equal",children:"equal()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"equal"}),"(",(0,i.jsx)(r.code,{children:"data"}),"): ",(0,i.jsx)(r.code,{children:"data is X509Crl"})]}),"\n"]}),"\n",(0,i.jsxs)(r.p,{children:["Returns ",(0,i.jsx)(r.code,{children:"true"})," if ASN.1 data is equal to another ASN.1 data, otherwise ",(0,i.jsx)(r.code,{children:"false"})]}),"\n",(0,i.jsx)(r.h4,{id:"parameters-2",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"data",children:"data"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"any"})}),"\n",(0,i.jsx)(r.p,{children:"Any data"}),"\n",(0,i.jsx)(r.h4,{id:"returns-2",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"data is X509Crl"})}),"\n",(0,i.jsx)(r.h4,{id:"inherited-from-2",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.equal"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"findrevoked",children:"findRevoked()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"findRevoked"}),"(",(0,i.jsx)(r.code,{children:"certOrSerialNumber"}),"): ",(0,i.jsx)(r.code,{children:"null"})," | ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/X509CrlEntry",children:(0,i.jsx)(r.code,{children:"X509CrlEntry"})})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Gets the CRL entry, with the given X509Certificate or certificate serialNumber."}),"\n",(0,i.jsx)(r.h4,{id:"parameters-3",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"certorserialnumber",children:"certOrSerialNumber"}),"\n",(0,i.jsx)(r.p,{children:"certificate | serialNumber"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"string"})," | ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/X509Certificate",children:(0,i.jsx)(r.code,{children:"X509Certificate"})})]}),"\n",(0,i.jsx)(r.h4,{id:"returns-3",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"null"})," | ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/X509CrlEntry",children:(0,i.jsx)(r.code,{children:"X509CrlEntry"})})]}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"getextension",children:"getExtension()"}),"\n",(0,i.jsx)(r.h4,{id:"call-signature",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"getExtension"}),"<",(0,i.jsx)(r.code,{children:"T"}),">(",(0,i.jsx)(r.code,{children:"type"}),"): ",(0,i.jsx)(r.code,{children:"null"})," | ",(0,i.jsx)(r.code,{children:"T"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Returns an extension of specified type"}),"\n",(0,i.jsx)(r.h5,{id:"type-parameters",children:"Type Parameters"}),"\n",(0,i.jsxs)(r.p,{children:["\u2022 ",(0,i.jsx)(r.strong,{children:"T"})," ",(0,i.jsx)(r.em,{children:"extends"})," ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,i.jsx)(r.code,{children:"Extension"})})]}),"\n",(0,i.jsx)(r.h5,{id:"parameters-4",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"type",children:"type"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,i.jsx)(r.h5,{id:"returns-4",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"null"})," | ",(0,i.jsx)(r.code,{children:"T"})]}),"\n",(0,i.jsx)(r.p,{children:"Extension or null"}),"\n",(0,i.jsx)(r.h4,{id:"call-signature-1",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"getExtension"}),"<",(0,i.jsx)(r.code,{children:"T"}),">(",(0,i.jsx)(r.code,{children:"type"}),"): ",(0,i.jsx)(r.code,{children:"null"})," | ",(0,i.jsx)(r.code,{children:"T"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Returns an extension of specified type"}),"\n",(0,i.jsx)(r.h5,{id:"type-parameters-1",children:"Type Parameters"}),"\n",(0,i.jsxs)(r.p,{children:["\u2022 ",(0,i.jsx)(r.strong,{children:"T"})," ",(0,i.jsx)(r.em,{children:"extends"})," ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,i.jsx)(r.code,{children:"Extension"})})]}),"\n",(0,i.jsx)(r.h5,{id:"parameters-5",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"type-1",children:"type"}),"\n",(0,i.jsxs)(r.p,{children:["(",(0,i.jsx)(r.code,{children:"raw"}),") => ",(0,i.jsx)(r.code,{children:"T"})]}),"\n",(0,i.jsx)(r.p,{children:"Extension type"}),"\n",(0,i.jsx)(r.h5,{id:"returns-5",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"null"})," | ",(0,i.jsx)(r.code,{children:"T"})]}),"\n",(0,i.jsx)(r.p,{children:"Extension or null"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"getextensions",children:"getExtensions()"}),"\n",(0,i.jsx)(r.p,{children:"Returns a list of extensions of specified type"}),"\n",(0,i.jsx)(r.h4,{id:"param",children:"Param"}),"\n",(0,i.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,i.jsx)(r.h4,{id:"call-signature-2",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"getExtensions"}),"<",(0,i.jsx)(r.code,{children:"T"}),">(",(0,i.jsx)(r.code,{children:"type"}),"): ",(0,i.jsx)(r.code,{children:"T"}),"[]"]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Returns a list of extensions of specified type"}),"\n",(0,i.jsx)(r.h5,{id:"type-parameters-2",children:"Type Parameters"}),"\n",(0,i.jsxs)(r.p,{children:["\u2022 ",(0,i.jsx)(r.strong,{children:"T"})," ",(0,i.jsx)(r.em,{children:"extends"})," ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,i.jsx)(r.code,{children:"Extension"})})]}),"\n",(0,i.jsx)(r.h5,{id:"parameters-6",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"type-2",children:"type"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,i.jsx)(r.h5,{id:"returns-6",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"T"}),"[]"]}),"\n",(0,i.jsx)(r.h5,{id:"param-1",children:"Param"}),"\n",(0,i.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,i.jsx)(r.h4,{id:"call-signature-3",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"getExtensions"}),"<",(0,i.jsx)(r.code,{children:"T"}),">(",(0,i.jsx)(r.code,{children:"type"}),"): ",(0,i.jsx)(r.code,{children:"T"}),"[]"]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Returns a list of extensions of specified type"}),"\n",(0,i.jsx)(r.h5,{id:"type-parameters-3",children:"Type Parameters"}),"\n",(0,i.jsxs)(r.p,{children:["\u2022 ",(0,i.jsx)(r.strong,{children:"T"})," ",(0,i.jsx)(r.em,{children:"extends"})," ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,i.jsx)(r.code,{children:"Extension"})})]}),"\n",(0,i.jsx)(r.h5,{id:"parameters-7",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"type-3",children:"type"}),"\n",(0,i.jsxs)(r.p,{children:["(",(0,i.jsx)(r.code,{children:"raw"}),") => ",(0,i.jsx)(r.code,{children:"T"})]}),"\n",(0,i.jsx)(r.p,{children:"Extension type"}),"\n",(0,i.jsx)(r.h5,{id:"returns-7",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"T"}),"[]"]}),"\n",(0,i.jsx)(r.h5,{id:"param-2",children:"Param"}),"\n",(0,i.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"gettextname",children:"getTextName()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"protected"})," ",(0,i.jsx)(r.strong,{children:"getTextName"}),"(): ",(0,i.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,i.jsx)(r.h4,{id:"returns-8",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.h4,{id:"inherited-from-3",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.getTextName"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"getthumbprint",children:"getThumbprint()"}),"\n",(0,i.jsx)(r.h4,{id:"call-signature-4",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"getThumbprint"}),"(",(0,i.jsx)(r.code,{children:"crypto"}),"?): ",(0,i.jsx)(r.code,{children:"Promise"}),"<",(0,i.jsx)(r.code,{children:"ArrayBuffer"}),">"]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Returns a SHA-1 certificate thumbprint"}),"\n",(0,i.jsx)(r.h5,{id:"parameters-8",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"crypto",children:"crypto?"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"Crypto"})}),"\n",(0,i.jsx)(r.p,{children:"Crypto provider. Default is from CryptoProvider"}),"\n",(0,i.jsx)(r.h5,{id:"returns-9",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"Promise"}),"<",(0,i.jsx)(r.code,{children:"ArrayBuffer"}),">"]}),"\n",(0,i.jsx)(r.h4,{id:"call-signature-5",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"getThumbprint"}),"(",(0,i.jsx)(r.code,{children:"algorithm"}),", ",(0,i.jsx)(r.code,{children:"crypto"}),"?): ",(0,i.jsx)(r.code,{children:"Promise"}),"<",(0,i.jsx)(r.code,{children:"ArrayBuffer"}),">"]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Returns a certificate thumbprint for specified mechanism"}),"\n",(0,i.jsx)(r.h5,{id:"parameters-9",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"algorithm",children:"algorithm"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"AlgorithmIdentifier"})}),"\n",(0,i.jsx)(r.p,{children:"Hash algorithm"}),"\n",(0,i.jsx)(r.h6,{id:"crypto-1",children:"crypto?"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"Crypto"})}),"\n",(0,i.jsx)(r.p,{children:"Crypto provider. Default is from CryptoProvider"}),"\n",(0,i.jsx)(r.h5,{id:"returns-10",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"Promise"}),"<",(0,i.jsx)(r.code,{children:"ArrayBuffer"}),">"]}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"oninit",children:"onInit()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"protected"})," ",(0,i.jsx)(r.strong,{children:"onInit"}),"(",(0,i.jsx)(r.code,{children:"asn"}),"): ",(0,i.jsx)(r.code,{children:"void"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Occurs on instance initialization"}),"\n",(0,i.jsx)(r.h4,{id:"parameters-10",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"asn-1",children:"asn"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"CertificateList"})}),"\n",(0,i.jsx)(r.p,{children:"ASN.1 object"}),"\n",(0,i.jsx)(r.h4,{id:"returns-11",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"void"})}),"\n",(0,i.jsx)(r.h4,{id:"overrides-3",children:"Overrides"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.onInit"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"tostring",children:"toString()"}),"\n",(0,i.jsx)(r.h4,{id:"call-signature-6",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"toString"}),"(): ",(0,i.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Returns encoded object in PEM format"}),"\n",(0,i.jsx)(r.h5,{id:"returns-12",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.h5,{id:"inherited-from-4",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.toString"})}),"\n",(0,i.jsx)(r.h4,{id:"call-signature-7",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"toString"}),"(",(0,i.jsx)(r.code,{children:"format"}),"): ",(0,i.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Returns encoded object in selected format"}),"\n",(0,i.jsx)(r.h5,{id:"parameters-11",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"format",children:"format"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"AsnExportType"})}),"\n",(0,i.jsx)(r.p,{children:"hex, base64, base64url, pem, asn, text"}),"\n",(0,i.jsx)(r.h5,{id:"returns-13",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.h5,{id:"inherited-from-5",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.toString"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"totextobject",children:"toTextObject()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"toTextObject"}),"(): ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/TextObject",children:(0,i.jsx)(r.code,{children:"TextObject"})})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Returns the object in textual representation"}),"\n",(0,i.jsx)(r.h4,{id:"returns-14",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/TextObject",children:(0,i.jsx)(r.code,{children:"TextObject"})})}),"\n",(0,i.jsx)(r.h4,{id:"inherited-from-6",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.toTextObject"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"totextobjectempty",children:"toTextObjectEmpty()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"protected"})," ",(0,i.jsx)(r.strong,{children:"toTextObjectEmpty"}),"(",(0,i.jsx)(r.code,{children:"value"}),"?): ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/TextObject",children:(0,i.jsx)(r.code,{children:"TextObject"})})]}),"\n"]}),"\n",(0,i.jsx)(r.h4,{id:"parameters-12",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"value",children:"value?"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.h4,{id:"returns-15",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/TextObject",children:(0,i.jsx)(r.code,{children:"TextObject"})})}),"\n",(0,i.jsx)(r.h4,{id:"inherited-from-7",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.toTextObjectEmpty"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"verify",children:"verify()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"verify"}),"(",(0,i.jsx)(r.code,{children:"params"}),", ",(0,i.jsx)(r.code,{children:"crypto"}),"): ",(0,i.jsx)(r.code,{children:"Promise"}),"<",(0,i.jsx)(r.code,{children:"boolean"}),">"]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Validates a crl signature"}),"\n",(0,i.jsx)(r.h4,{id:"parameters-13",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"params",children:"params"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.a,{href:"/x509/docs/api/interfaces/X509CrlVerifyParams",children:(0,i.jsx)(r.code,{children:"X509CrlVerifyParams"})})}),"\n",(0,i.jsx)(r.p,{children:"Verification parameters"}),"\n",(0,i.jsx)(r.h5,{id:"crypto-2",children:"crypto"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"Crypto"})," = ",(0,i.jsx)(r.code,{children:"..."})]}),"\n",(0,i.jsx)(r.p,{children:"Crypto provider. Default is from CryptoProvider"}),"\n",(0,i.jsx)(r.h4,{id:"returns-16",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"Promise"}),"<",(0,i.jsx)(r.code,{children:"boolean"}),">"]}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"isasnencoded",children:"isAsnEncoded()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"isAsnEncoded"}),"(",(0,i.jsx)(r.code,{children:"data"}),"): ",(0,i.jsx)(r.code,{children:"data is AsnEncodedType"})]}),"\n"]}),"\n",(0,i.jsx)(r.h4,{id:"parameters-14",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"data-1",children:"data"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"any"})}),"\n",(0,i.jsx)(r.h4,{id:"returns-17",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"data is AsnEncodedType"})}),"\n",(0,i.jsx)(r.h4,{id:"inherited-from-8",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.isAsnEncoded"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"toarraybuffer",children:"toArrayBuffer()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"toArrayBuffer"}),"(",(0,i.jsx)(r.code,{children:"raw"}),"): ",(0,i.jsx)(r.code,{children:"ArrayBuffer"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Converts encoded raw to ArrayBuffer. Supported formats are HEX, DER, Base64, Base64Url, PEM"}),"\n",(0,i.jsx)(r.h4,{id:"parameters-15",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"raw-1",children:"raw"}),"\n",(0,i.jsx)(r.p,{children:"Encoded data"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"string"})," | ",(0,i.jsx)(r.code,{children:"BufferSource"})]}),"\n",(0,i.jsx)(r.h4,{id:"returns-18",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"ArrayBuffer"})}),"\n",(0,i.jsx)(r.h4,{id:"inherited-from-9",children:"Inherited from"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"PemData.toArrayBuffer"})})]})}function x(e={}){const{wrapper:r}={...(0,l.R)(),...e.components};return r?(0,i.jsx)(r,{...e,children:(0,i.jsx)(h,{...e})}):h(e)}},8453:(e,r,n)=>{n.d(r,{R:()=>d,x:()=>t});var s=n(6540);const i={},l=s.createContext(i);function d(e){const r=s.useContext(l);return s.useMemo((function(){return"function"==typeof e?e(r):{...r,...e}}),[r,e])}function t(e){let r;return r=e.disableParentContext?"function"==typeof e.components?e.components(i):e.components||i:d(e.components),s.createElement(l.Provider,{value:r},e.children)}}}]);