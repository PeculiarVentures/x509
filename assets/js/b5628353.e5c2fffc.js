"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[5303],{7534:(e,r,n)=>{n.r(r),n.d(r,{assets:()=>c,contentTitle:()=>t,default:()=>o,frontMatter:()=>d,metadata:()=>l,toc:()=>h});var s=n(4848),i=n(8453);const d={},t="X509Crl",l={id:"api/classes/X509Crl",title:"X509Crl",description:"Representation of X.509 Certificate Revocation List (CRL)",source:"@site/docs/api/classes/X509Crl.md",sourceDirName:"api/classes",slug:"/api/classes/X509Crl",permalink:"/x509/docs/api/classes/X509Crl",draft:!1,unlisted:!1,tags:[],version:"current",frontMatter:{},sidebar:"docs",previous:{title:"X509ChainBuilder",permalink:"/x509/docs/api/classes/X509ChainBuilder"},next:{title:"X509CrlEntry",permalink:"/x509/docs/api/classes/X509CrlEntry"}},c={},h=[{value:"Extends",id:"extends",level:2},{value:"Constructors",id:"constructors",level:2},{value:"new X509Crl()",id:"new-x509crl",level:3},{value:"Parameters",id:"parameters",level:4},{value:"Returns",id:"returns",level:4},{value:"Overrides",id:"overrides",level:4},{value:"new X509Crl()",id:"new-x509crl-1",level:3},{value:"Parameters",id:"parameters-1",level:4},{value:"Returns",id:"returns-1",level:4},{value:"Overrides",id:"overrides-1",level:4},{value:"Properties",id:"properties",level:2},{value:"entries",id:"entries",level:3},{value:"extensions",id:"extensions",level:3},{value:"issuer",id:"issuer",level:3},{value:"issuerName",id:"issuername",level:3},{value:"nextUpdate?",id:"nextupdate",level:3},{value:"rawData",id:"rawdata",level:3},{value:"Inherited from",id:"inherited-from",level:4},{value:"signature",id:"signature",level:3},{value:"signatureAlgorithm",id:"signaturealgorithm",level:3},{value:"tag",id:"tag",level:3},{value:"Overrides",id:"overrides-2",level:4},{value:"thisUpdate",id:"thisupdate",level:3},{value:"version?",id:"version",level:3},{value:"NAME",id:"name",level:3},{value:"Inherited from",id:"inherited-from-1",level:4},{value:"Methods",id:"methods",level:2},{value:"equal()",id:"equal",level:3},{value:"Parameters",id:"parameters-2",level:4},{value:"Returns",id:"returns-2",level:4},{value:"Inherited from",id:"inherited-from-2",level:4},{value:"findRevoked()",id:"findrevoked",level:3},{value:"Parameters",id:"parameters-3",level:4},{value:"Returns",id:"returns-3",level:4},{value:"getExtension()",id:"getextension",level:3},{value:"getExtension(type)",id:"getextensiontype",level:4},{value:"Type Parameters",id:"type-parameters",level:5},{value:"Parameters",id:"parameters-4",level:5},{value:"Returns",id:"returns-4",level:5},{value:"getExtension(type)",id:"getextensiontype-1",level:4},{value:"Type Parameters",id:"type-parameters-1",level:5},{value:"Parameters",id:"parameters-5",level:5},{value:"Returns",id:"returns-5",level:5},{value:"getExtensions()",id:"getextensions",level:3},{value:"Param",id:"param",level:4},{value:"getExtensions(type)",id:"getextensionstype",level:4},{value:"Type Parameters",id:"type-parameters-2",level:5},{value:"Parameters",id:"parameters-6",level:5},{value:"Returns",id:"returns-6",level:5},{value:"Param",id:"param-1",level:5},{value:"getExtensions(type)",id:"getextensionstype-1",level:4},{value:"Type Parameters",id:"type-parameters-3",level:5},{value:"Parameters",id:"parameters-7",level:5},{value:"Returns",id:"returns-7",level:5},{value:"Param",id:"param-2",level:5},{value:"getTextName()",id:"gettextname",level:3},{value:"Returns",id:"returns-8",level:4},{value:"Inherited from",id:"inherited-from-3",level:4},{value:"getThumbprint()",id:"getthumbprint",level:3},{value:"getThumbprint(crypto)",id:"getthumbprintcrypto",level:4},{value:"Parameters",id:"parameters-8",level:5},{value:"Returns",id:"returns-9",level:5},{value:"getThumbprint(algorithm, crypto)",id:"getthumbprintalgorithm-crypto",level:4},{value:"Parameters",id:"parameters-9",level:5},{value:"Returns",id:"returns-10",level:5},{value:"onInit()",id:"oninit",level:3},{value:"Parameters",id:"parameters-10",level:4},{value:"Returns",id:"returns-11",level:4},{value:"Overrides",id:"overrides-3",level:4},{value:"toString()",id:"tostring",level:3},{value:"toString()",id:"tostring-1",level:4},{value:"Returns",id:"returns-12",level:5},{value:"Inherited from",id:"inherited-from-4",level:5},{value:"toString(format)",id:"tostringformat",level:4},{value:"Parameters",id:"parameters-11",level:5},{value:"Returns",id:"returns-13",level:5},{value:"Inherited from",id:"inherited-from-5",level:5},{value:"toTextObject()",id:"totextobject",level:3},{value:"Returns",id:"returns-14",level:4},{value:"Inherited from",id:"inherited-from-6",level:4},{value:"toTextObjectEmpty()",id:"totextobjectempty",level:3},{value:"Parameters",id:"parameters-12",level:4},{value:"Returns",id:"returns-15",level:4},{value:"Inherited from",id:"inherited-from-7",level:4},{value:"verify()",id:"verify",level:3},{value:"Parameters",id:"parameters-13",level:4},{value:"Returns",id:"returns-16",level:4},{value:"isAsnEncoded()",id:"isasnencoded",level:3},{value:"Parameters",id:"parameters-14",level:4},{value:"Returns",id:"returns-17",level:4},{value:"Inherited from",id:"inherited-from-8",level:4},{value:"toArrayBuffer()",id:"toarraybuffer",level:3},{value:"Parameters",id:"parameters-15",level:4},{value:"Returns",id:"returns-18",level:4},{value:"Inherited from",id:"inherited-from-9",level:4}];function a(e){const r={a:"a",blockquote:"blockquote",code:"code",em:"em",h1:"h1",h2:"h2",h3:"h3",h4:"h4",h5:"h5",header:"header",hr:"hr",li:"li",p:"p",strong:"strong",ul:"ul",...(0,i.R)(),...e.components};return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(r.header,{children:(0,s.jsx)(r.h1,{id:"x509crl",children:"X509Crl"})}),"\n",(0,s.jsx)(r.p,{children:"Representation of X.509 Certificate Revocation List (CRL)"}),"\n",(0,s.jsx)(r.h2,{id:"extends",children:"Extends"}),"\n",(0,s.jsxs)(r.ul,{children:["\n",(0,s.jsxs)(r.li,{children:[(0,s.jsx)(r.code,{children:"PemData"}),"<",(0,s.jsx)(r.code,{children:"CertificateList"}),">"]}),"\n"]}),"\n",(0,s.jsx)(r.h2,{id:"constructors",children:"Constructors"}),"\n",(0,s.jsx)(r.h3,{id:"new-x509crl",children:"new X509Crl()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"new X509Crl"}),"(",(0,s.jsx)(r.code,{children:"asn"}),"): ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/X509Crl",children:(0,s.jsx)(r.code,{children:"X509Crl"})})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Creates a new instance from ASN.1 CertificateList object"}),"\n",(0,s.jsx)(r.h4,{id:"parameters",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"asn"}),": ",(0,s.jsx)(r.code,{children:"CertificateList"})]}),"\n",(0,s.jsx)(r.p,{children:"ASN.1 CertificateList object"}),"\n",(0,s.jsx)(r.h4,{id:"returns",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/X509Crl",children:(0,s.jsx)(r.code,{children:"X509Crl"})})}),"\n",(0,s.jsx)(r.h4,{id:"overrides",children:"Overrides"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData<CertificateList>.constructor"})}),"\n",(0,s.jsx)(r.h3,{id:"new-x509crl-1",children:"new X509Crl()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"new X509Crl"}),"(",(0,s.jsx)(r.code,{children:"raw"}),"): ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/X509Crl",children:(0,s.jsx)(r.code,{children:"X509Crl"})})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Creates a new instance"}),"\n",(0,s.jsx)(r.h4,{id:"parameters-1",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"raw"}),": ",(0,s.jsx)(r.code,{children:"AsnEncodedType"})]}),"\n",(0,s.jsx)(r.p,{children:"Encoded buffer (DER, PEM, HEX, Base64, Base64Url)"}),"\n",(0,s.jsx)(r.h4,{id:"returns-1",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/X509Crl",children:(0,s.jsx)(r.code,{children:"X509Crl"})})}),"\n",(0,s.jsx)(r.h4,{id:"overrides-1",children:"Overrides"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData<CertificateList>.constructor"})}),"\n",(0,s.jsx)(r.h2,{id:"properties",children:"Properties"}),"\n",(0,s.jsx)(r.h3,{id:"entries",children:"entries"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"entries"}),": readonly ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/X509CrlEntry",children:(0,s.jsx)(r.code,{children:"X509CrlEntry"})}),"[]"]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets a crlEntries from the CRL"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"extensions",children:"extensions"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"extensions"}),": ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,s.jsx)(r.code,{children:"Extension"})}),"[]"]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gts a list of crl extensions"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"issuer",children:"issuer"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"issuer"}),": ",(0,s.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets a string issuer name"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"issuername",children:"issuerName"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"issuerName"}),": ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/Name",children:(0,s.jsx)(r.code,{children:"Name"})})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets the issuer value from the crl as an Name"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"nextupdate",children:"nextUpdate?"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"optional"})," ",(0,s.jsx)(r.strong,{children:"nextUpdate"}),": ",(0,s.jsx)(r.code,{children:"Date"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets a nextUpdate date from the CRL"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"rawdata",children:"rawData"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"readonly"})," ",(0,s.jsx)(r.strong,{children:"rawData"}),": ",(0,s.jsx)(r.code,{children:"ArrayBuffer"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets a DER encoded buffer"}),"\n",(0,s.jsx)(r.h4,{id:"inherited-from",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.rawData"})}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"signature",children:"signature"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"signature"}),": ",(0,s.jsx)(r.code,{children:"ArrayBuffer"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets a signature"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"signaturealgorithm",children:"signatureAlgorithm"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"signatureAlgorithm"}),": ",(0,s.jsx)(r.a,{href:"/x509/docs/api/interfaces/HashedAlgorithm",children:(0,s.jsx)(r.code,{children:"HashedAlgorithm"})})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets a signature algorithm"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"tag",children:"tag"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"protected"})," ",(0,s.jsx)(r.code,{children:"readonly"})," ",(0,s.jsx)(r.strong,{children:"tag"}),": ",(0,s.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"PEM tag"}),"\n",(0,s.jsx)(r.h4,{id:"overrides-2",children:"Overrides"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.tag"})}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"thisupdate",children:"thisUpdate"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"thisUpdate"}),": ",(0,s.jsx)(r.code,{children:"Date"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets a thisUpdate date from the CRL"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"version",children:"version?"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"optional"})," ",(0,s.jsx)(r.strong,{children:"version"}),": ",(0,s.jsx)(r.code,{children:"Version"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets a version"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"name",children:"NAME"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"static"})," ",(0,s.jsx)(r.strong,{children:"NAME"}),": ",(0,s.jsx)(r.code,{children:"string"})," = ",(0,s.jsx)(r.code,{children:'"ASN"'})]}),"\n"]}),"\n",(0,s.jsx)(r.h4,{id:"inherited-from-1",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.NAME"})}),"\n",(0,s.jsx)(r.h2,{id:"methods",children:"Methods"}),"\n",(0,s.jsx)(r.h3,{id:"equal",children:"equal()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"equal"}),"(",(0,s.jsx)(r.code,{children:"data"}),"): ",(0,s.jsx)(r.code,{children:"data is X509Crl"})]}),"\n"]}),"\n",(0,s.jsxs)(r.p,{children:["Returns ",(0,s.jsx)(r.code,{children:"true"})," if ASN.1 data is equal to another ASN.1 data, otherwise ",(0,s.jsx)(r.code,{children:"false"})]}),"\n",(0,s.jsx)(r.h4,{id:"parameters-2",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"data"}),": ",(0,s.jsx)(r.code,{children:"any"})]}),"\n",(0,s.jsx)(r.p,{children:"Any data"}),"\n",(0,s.jsx)(r.h4,{id:"returns-2",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"data is X509Crl"})}),"\n",(0,s.jsx)(r.h4,{id:"inherited-from-2",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.equal"})}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"findrevoked",children:"findRevoked()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"findRevoked"}),"(",(0,s.jsx)(r.code,{children:"certOrSerialNumber"}),"): ",(0,s.jsx)(r.code,{children:"null"})," | ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/X509CrlEntry",children:(0,s.jsx)(r.code,{children:"X509CrlEntry"})})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Gets the CRL entry, with the given X509Certificate or certificate serialNumber."}),"\n",(0,s.jsx)(r.h4,{id:"parameters-3",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"certOrSerialNumber"}),": ",(0,s.jsx)(r.code,{children:"string"})," | ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/X509Certificate",children:(0,s.jsx)(r.code,{children:"X509Certificate"})})]}),"\n",(0,s.jsx)(r.p,{children:"certificate | serialNumber"}),"\n",(0,s.jsx)(r.h4,{id:"returns-3",children:"Returns"}),"\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"null"})," | ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/X509CrlEntry",children:(0,s.jsx)(r.code,{children:"X509CrlEntry"})})]}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"getextension",children:"getExtension()"}),"\n",(0,s.jsx)(r.h4,{id:"getextensiontype",children:"getExtension(type)"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"getExtension"}),"<",(0,s.jsx)(r.code,{children:"T"}),">(",(0,s.jsx)(r.code,{children:"type"}),"): ",(0,s.jsx)(r.code,{children:"null"})," | ",(0,s.jsx)(r.code,{children:"T"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Returns an extension of specified type"}),"\n",(0,s.jsx)(r.h5,{id:"type-parameters",children:"Type Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"T"})," ",(0,s.jsx)(r.em,{children:"extends"})," ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,s.jsx)(r.code,{children:"Extension"})})]}),"\n",(0,s.jsx)(r.h5,{id:"parameters-4",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"type"}),": ",(0,s.jsx)(r.code,{children:"string"})]}),"\n",(0,s.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,s.jsx)(r.h5,{id:"returns-4",children:"Returns"}),"\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"null"})," | ",(0,s.jsx)(r.code,{children:"T"})]}),"\n",(0,s.jsx)(r.p,{children:"Extension or null"}),"\n",(0,s.jsx)(r.h4,{id:"getextensiontype-1",children:"getExtension(type)"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"getExtension"}),"<",(0,s.jsx)(r.code,{children:"T"}),">(",(0,s.jsx)(r.code,{children:"type"}),"): ",(0,s.jsx)(r.code,{children:"null"})," | ",(0,s.jsx)(r.code,{children:"T"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Returns an extension of specified type"}),"\n",(0,s.jsx)(r.h5,{id:"type-parameters-1",children:"Type Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"T"})," ",(0,s.jsx)(r.em,{children:"extends"})," ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,s.jsx)(r.code,{children:"Extension"})})]}),"\n",(0,s.jsx)(r.h5,{id:"parameters-5",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"type"})]}),"\n",(0,s.jsx)(r.p,{children:"Extension type"}),"\n",(0,s.jsx)(r.h5,{id:"returns-5",children:"Returns"}),"\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"null"})," | ",(0,s.jsx)(r.code,{children:"T"})]}),"\n",(0,s.jsx)(r.p,{children:"Extension or null"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"getextensions",children:"getExtensions()"}),"\n",(0,s.jsx)(r.p,{children:"Returns a list of extensions of specified type"}),"\n",(0,s.jsx)(r.h4,{id:"param",children:"Param"}),"\n",(0,s.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,s.jsx)(r.h4,{id:"getextensionstype",children:"getExtensions(type)"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"getExtensions"}),"<",(0,s.jsx)(r.code,{children:"T"}),">(",(0,s.jsx)(r.code,{children:"type"}),"): ",(0,s.jsx)(r.code,{children:"T"}),"[]"]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Returns a list of extensions of specified type"}),"\n",(0,s.jsx)(r.h5,{id:"type-parameters-2",children:"Type Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"T"})," ",(0,s.jsx)(r.em,{children:"extends"})," ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,s.jsx)(r.code,{children:"Extension"})})]}),"\n",(0,s.jsx)(r.h5,{id:"parameters-6",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"type"}),": ",(0,s.jsx)(r.code,{children:"string"})]}),"\n",(0,s.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,s.jsx)(r.h5,{id:"returns-6",children:"Returns"}),"\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"T"}),"[]"]}),"\n",(0,s.jsx)(r.h5,{id:"param-1",children:"Param"}),"\n",(0,s.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,s.jsx)(r.h4,{id:"getextensionstype-1",children:"getExtensions(type)"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"getExtensions"}),"<",(0,s.jsx)(r.code,{children:"T"}),">(",(0,s.jsx)(r.code,{children:"type"}),"): ",(0,s.jsx)(r.code,{children:"T"}),"[]"]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Returns a list of extensions of specified type"}),"\n",(0,s.jsx)(r.h5,{id:"type-parameters-3",children:"Type Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"T"})," ",(0,s.jsx)(r.em,{children:"extends"})," ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/Extension",children:(0,s.jsx)(r.code,{children:"Extension"})})]}),"\n",(0,s.jsx)(r.h5,{id:"parameters-7",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"type"})]}),"\n",(0,s.jsx)(r.p,{children:"Extension type"}),"\n",(0,s.jsx)(r.h5,{id:"returns-7",children:"Returns"}),"\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"T"}),"[]"]}),"\n",(0,s.jsx)(r.h5,{id:"param-2",children:"Param"}),"\n",(0,s.jsx)(r.p,{children:"Extension identifier"}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"gettextname",children:"getTextName()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"protected"})," ",(0,s.jsx)(r.strong,{children:"getTextName"}),"(): ",(0,s.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,s.jsx)(r.h4,{id:"returns-8",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"string"})}),"\n",(0,s.jsx)(r.h4,{id:"inherited-from-3",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.getTextName"})}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"getthumbprint",children:"getThumbprint()"}),"\n",(0,s.jsx)(r.h4,{id:"getthumbprintcrypto",children:"getThumbprint(crypto)"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"getThumbprint"}),"(",(0,s.jsx)(r.code,{children:"crypto"}),"?): ",(0,s.jsx)(r.code,{children:"Promise"}),"<",(0,s.jsx)(r.code,{children:"ArrayBuffer"}),">"]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Returns a SHA-1 certificate thumbprint"}),"\n",(0,s.jsx)(r.h5,{id:"parameters-8",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"crypto?"}),": ",(0,s.jsx)(r.code,{children:"Crypto"})]}),"\n",(0,s.jsx)(r.p,{children:"Crypto provider. Default is from CryptoProvider"}),"\n",(0,s.jsx)(r.h5,{id:"returns-9",children:"Returns"}),"\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"Promise"}),"<",(0,s.jsx)(r.code,{children:"ArrayBuffer"}),">"]}),"\n",(0,s.jsx)(r.h4,{id:"getthumbprintalgorithm-crypto",children:"getThumbprint(algorithm, crypto)"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"getThumbprint"}),"(",(0,s.jsx)(r.code,{children:"algorithm"}),", ",(0,s.jsx)(r.code,{children:"crypto"}),"?): ",(0,s.jsx)(r.code,{children:"Promise"}),"<",(0,s.jsx)(r.code,{children:"ArrayBuffer"}),">"]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Returns a certificate thumbprint for specified mechanism"}),"\n",(0,s.jsx)(r.h5,{id:"parameters-9",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"algorithm"}),": ",(0,s.jsx)(r.code,{children:"AlgorithmIdentifier"})]}),"\n",(0,s.jsx)(r.p,{children:"Hash algorithm"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"crypto?"}),": ",(0,s.jsx)(r.code,{children:"Crypto"})]}),"\n",(0,s.jsx)(r.p,{children:"Crypto provider. Default is from CryptoProvider"}),"\n",(0,s.jsx)(r.h5,{id:"returns-10",children:"Returns"}),"\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"Promise"}),"<",(0,s.jsx)(r.code,{children:"ArrayBuffer"}),">"]}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"oninit",children:"onInit()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"protected"})," ",(0,s.jsx)(r.strong,{children:"onInit"}),"(",(0,s.jsx)(r.code,{children:"asn"}),"): ",(0,s.jsx)(r.code,{children:"void"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Occurs on instance initialization"}),"\n",(0,s.jsx)(r.h4,{id:"parameters-10",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"asn"}),": ",(0,s.jsx)(r.code,{children:"CertificateList"})]}),"\n",(0,s.jsx)(r.p,{children:"ASN.1 object"}),"\n",(0,s.jsx)(r.h4,{id:"returns-11",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"void"})}),"\n",(0,s.jsx)(r.h4,{id:"overrides-3",children:"Overrides"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.onInit"})}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"tostring",children:"toString()"}),"\n",(0,s.jsx)(r.h4,{id:"tostring-1",children:"toString()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"toString"}),"(): ",(0,s.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Returns encoded object in PEM format"}),"\n",(0,s.jsx)(r.h5,{id:"returns-12",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"string"})}),"\n",(0,s.jsx)(r.h5,{id:"inherited-from-4",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.toString"})}),"\n",(0,s.jsx)(r.h4,{id:"tostringformat",children:"toString(format)"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"toString"}),"(",(0,s.jsx)(r.code,{children:"format"}),"): ",(0,s.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Returns encoded object in selected format"}),"\n",(0,s.jsx)(r.h5,{id:"parameters-11",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"format"}),": ",(0,s.jsx)(r.code,{children:"AsnExportType"})]}),"\n",(0,s.jsx)(r.p,{children:"hex, base64, base64url, pem, asn, text"}),"\n",(0,s.jsx)(r.h5,{id:"returns-13",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"string"})}),"\n",(0,s.jsx)(r.h5,{id:"inherited-from-5",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.toString"})}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"totextobject",children:"toTextObject()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"toTextObject"}),"(): ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/TextObject",children:(0,s.jsx)(r.code,{children:"TextObject"})})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Returns the object in textual representation"}),"\n",(0,s.jsx)(r.h4,{id:"returns-14",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/TextObject",children:(0,s.jsx)(r.code,{children:"TextObject"})})}),"\n",(0,s.jsx)(r.h4,{id:"inherited-from-6",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.toTextObject"})}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"totextobjectempty",children:"toTextObjectEmpty()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"protected"})," ",(0,s.jsx)(r.strong,{children:"toTextObjectEmpty"}),"(",(0,s.jsx)(r.code,{children:"value"}),"?): ",(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/TextObject",children:(0,s.jsx)(r.code,{children:"TextObject"})})]}),"\n"]}),"\n",(0,s.jsx)(r.h4,{id:"parameters-12",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"value?"}),": ",(0,s.jsx)(r.code,{children:"string"})]}),"\n",(0,s.jsx)(r.h4,{id:"returns-15",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.a,{href:"/x509/docs/api/classes/TextObject",children:(0,s.jsx)(r.code,{children:"TextObject"})})}),"\n",(0,s.jsx)(r.h4,{id:"inherited-from-7",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.toTextObjectEmpty"})}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"verify",children:"verify()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.strong,{children:"verify"}),"(",(0,s.jsx)(r.code,{children:"params"}),", ",(0,s.jsx)(r.code,{children:"crypto"}),"): ",(0,s.jsx)(r.code,{children:"Promise"}),"<",(0,s.jsx)(r.code,{children:"boolean"}),">"]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Validates a crl signature"}),"\n",(0,s.jsx)(r.h4,{id:"parameters-13",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"params"}),": ",(0,s.jsx)(r.a,{href:"/x509/docs/api/interfaces/X509CrlVerifyParams",children:(0,s.jsx)(r.code,{children:"X509CrlVerifyParams"})})]}),"\n",(0,s.jsx)(r.p,{children:"Verification parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"crypto"}),": ",(0,s.jsx)(r.code,{children:"Crypto"})," = ",(0,s.jsx)(r.code,{children:"..."})]}),"\n",(0,s.jsx)(r.p,{children:"Crypto provider. Default is from CryptoProvider"}),"\n",(0,s.jsx)(r.h4,{id:"returns-16",children:"Returns"}),"\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"Promise"}),"<",(0,s.jsx)(r.code,{children:"boolean"}),">"]}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"isasnencoded",children:"isAsnEncoded()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"static"})," ",(0,s.jsx)(r.strong,{children:"isAsnEncoded"}),"(",(0,s.jsx)(r.code,{children:"data"}),"): ",(0,s.jsx)(r.code,{children:"data is AsnEncodedType"})]}),"\n"]}),"\n",(0,s.jsx)(r.h4,{id:"parameters-14",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"data"}),": ",(0,s.jsx)(r.code,{children:"any"})]}),"\n",(0,s.jsx)(r.h4,{id:"returns-17",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"data is AsnEncodedType"})}),"\n",(0,s.jsx)(r.h4,{id:"inherited-from-8",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.isAsnEncoded"})}),"\n",(0,s.jsx)(r.hr,{}),"\n",(0,s.jsx)(r.h3,{id:"toarraybuffer",children:"toArrayBuffer()"}),"\n",(0,s.jsxs)(r.blockquote,{children:["\n",(0,s.jsxs)(r.p,{children:[(0,s.jsx)(r.code,{children:"static"})," ",(0,s.jsx)(r.strong,{children:"toArrayBuffer"}),"(",(0,s.jsx)(r.code,{children:"raw"}),"): ",(0,s.jsx)(r.code,{children:"ArrayBuffer"})]}),"\n"]}),"\n",(0,s.jsx)(r.p,{children:"Converts encoded raw to ArrayBuffer. Supported formats are HEX, DER, Base64, Base64Url, PEM"}),"\n",(0,s.jsx)(r.h4,{id:"parameters-15",children:"Parameters"}),"\n",(0,s.jsxs)(r.p,{children:["\u2022 ",(0,s.jsx)(r.strong,{children:"raw"}),": ",(0,s.jsx)(r.code,{children:"string"})," | ",(0,s.jsx)(r.code,{children:"BufferSource"})]}),"\n",(0,s.jsx)(r.p,{children:"Encoded data"}),"\n",(0,s.jsx)(r.h4,{id:"returns-18",children:"Returns"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"ArrayBuffer"})}),"\n",(0,s.jsx)(r.h4,{id:"inherited-from-9",children:"Inherited from"}),"\n",(0,s.jsx)(r.p,{children:(0,s.jsx)(r.code,{children:"PemData.toArrayBuffer"})})]})}function o(e={}){const{wrapper:r}={...(0,i.R)(),...e.components};return r?(0,s.jsx)(r,{...e,children:(0,s.jsx)(a,{...e})}):a(e)}},8453:(e,r,n)=>{n.d(r,{R:()=>t,x:()=>l});var s=n(6540);const i={},d=s.createContext(i);function t(e){const r=s.useContext(d);return s.useMemo((function(){return"function"==typeof e?e(r):{...r,...e}}),[r,e])}function l(e){let r;return r=e.disableParentContext?"function"==typeof e.components?e.components(i):e.components||i:t(e.components),s.createElement(d.Provider,{value:r},e.children)}}}]);