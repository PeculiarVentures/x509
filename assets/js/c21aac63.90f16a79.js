"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[7719],{4402:(e,r,s)=>{s.r(r),s.d(r,{assets:()=>t,contentTitle:()=>l,default:()=>o,frontMatter:()=>c,metadata:()=>n,toc:()=>a});const n=JSON.parse('{"id":"api/classes/PemConverter","title":"PemConverter","description":"Represents PEM Converter.","source":"@site/docs/api/classes/PemConverter.md","sourceDirName":"api/classes","slug":"/api/classes/PemConverter","permalink":"/x509/docs/api/classes/PemConverter","draft":false,"unlisted":false,"tags":[],"version":"current","frontMatter":{},"sidebar":"docs","previous":{"title":"OidSerializer","permalink":"/x509/docs/api/classes/OidSerializer"},"next":{"title":"Pkcs10CertificateRequest","permalink":"/x509/docs/api/classes/Pkcs10CertificateRequest"}}');var i=s(4848),d=s(8453);const c={},l="PemConverter",t={},a=[{value:"Constructors",id:"constructors",level:2},{value:"new PemConverter()",id:"new-pemconverter",level:3},{value:"Returns",id:"returns",level:4},{value:"Properties",id:"properties",level:2},{value:"CertificateRequestTag",id:"certificaterequesttag",level:3},{value:"CertificateTag",id:"certificatetag",level:3},{value:"CrlTag",id:"crltag",level:3},{value:"PrivateKeyTag",id:"privatekeytag",level:3},{value:"PublicKeyTag",id:"publickeytag",level:3},{value:"Methods",id:"methods",level:2},{value:"decode()",id:"decode",level:3},{value:"Parameters",id:"parameters",level:4},{value:"pem",id:"pem",level:5},{value:"Returns",id:"returns-1",level:4},{value:"decodeFirst()",id:"decodefirst",level:3},{value:"Parameters",id:"parameters-1",level:4},{value:"pem",id:"pem-1",level:5},{value:"Returns",id:"returns-2",level:4},{value:"Throw",id:"throw",level:4},{value:"decodeWithHeaders()",id:"decodewithheaders",level:3},{value:"Parameters",id:"parameters-2",level:4},{value:"pem",id:"pem-2",level:5},{value:"Returns",id:"returns-3",level:4},{value:"encode()",id:"encode",level:3},{value:"Call Signature",id:"call-signature",level:4},{value:"Parameters",id:"parameters-3",level:5},{value:"structs",id:"structs",level:6},{value:"Returns",id:"returns-4",level:5},{value:"Call Signature",id:"call-signature-1",level:4},{value:"Parameters",id:"parameters-4",level:5},{value:"rawData",id:"rawdata",level:6},{value:"tag",id:"tag",level:6},{value:"Returns",id:"returns-5",level:5},{value:"Call Signature",id:"call-signature-2",level:4},{value:"Parameters",id:"parameters-5",level:5},{value:"rawData",id:"rawdata-1",level:6},{value:"tag",id:"tag-1",level:6},{value:"Returns",id:"returns-6",level:5},{value:"isPem()",id:"ispem",level:3},{value:"Parameters",id:"parameters-6",level:4},{value:"data",id:"data",level:5},{value:"Returns",id:"returns-7",level:4}];function h(e){const r={a:"a",blockquote:"blockquote",code:"code",h1:"h1",h2:"h2",h3:"h3",h4:"h4",h5:"h5",h6:"h6",header:"header",hr:"hr",p:"p",strong:"strong",...(0,d.R)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(r.header,{children:(0,i.jsx)(r.h1,{id:"pemconverter",children:"PemConverter"})}),"\n",(0,i.jsx)(r.p,{children:"Represents PEM Converter."}),"\n",(0,i.jsx)(r.h2,{id:"constructors",children:"Constructors"}),"\n",(0,i.jsx)(r.h3,{id:"new-pemconverter",children:"new PemConverter()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.strong,{children:"new PemConverter"}),"(): ",(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/PemConverter",children:(0,i.jsx)(r.code,{children:"PemConverter"})})]}),"\n"]}),"\n",(0,i.jsx)(r.h4,{id:"returns",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.a,{href:"/x509/docs/api/classes/PemConverter",children:(0,i.jsx)(r.code,{children:"PemConverter"})})}),"\n",(0,i.jsx)(r.h2,{id:"properties",children:"Properties"}),"\n",(0,i.jsx)(r.h3,{id:"certificaterequesttag",children:"CertificateRequestTag"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"CertificateRequestTag"}),": ",(0,i.jsx)(r.code,{children:"string"})," = ",(0,i.jsx)(r.code,{children:'"CERTIFICATE REQUEST"'})]}),"\n"]}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"certificatetag",children:"CertificateTag"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"CertificateTag"}),": ",(0,i.jsx)(r.code,{children:"string"})," = ",(0,i.jsx)(r.code,{children:'"CERTIFICATE"'})]}),"\n"]}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"crltag",children:"CrlTag"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"CrlTag"}),": ",(0,i.jsx)(r.code,{children:"string"})," = ",(0,i.jsx)(r.code,{children:'"CRL"'})]}),"\n"]}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"privatekeytag",children:"PrivateKeyTag"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"PrivateKeyTag"}),": ",(0,i.jsx)(r.code,{children:"string"})," = ",(0,i.jsx)(r.code,{children:'"PRIVATE KEY"'})]}),"\n"]}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"publickeytag",children:"PublicKeyTag"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"PublicKeyTag"}),": ",(0,i.jsx)(r.code,{children:"string"})," = ",(0,i.jsx)(r.code,{children:'"PUBLIC KEY"'})]}),"\n"]}),"\n",(0,i.jsx)(r.h2,{id:"methods",children:"Methods"}),"\n",(0,i.jsx)(r.h3,{id:"decode",children:"decode()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"decode"}),"(",(0,i.jsx)(r.code,{children:"pem"}),"): ",(0,i.jsx)(r.code,{children:"ArrayBuffer"}),"[]"]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Decodes PEM to a list of raws"}),"\n",(0,i.jsx)(r.h4,{id:"parameters",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"pem",children:"pem"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.p,{children:"message in PEM format"}),"\n",(0,i.jsx)(r.h4,{id:"returns-1",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"ArrayBuffer"}),"[]"]}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"decodefirst",children:"decodeFirst()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"decodeFirst"}),"(",(0,i.jsx)(r.code,{children:"pem"}),"): ",(0,i.jsx)(r.code,{children:"ArrayBuffer"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Decodes PEM and returns first item from the list"}),"\n",(0,i.jsx)(r.h4,{id:"parameters-1",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"pem-1",children:"pem"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.p,{children:"message in PEM format"}),"\n",(0,i.jsx)(r.h4,{id:"returns-2",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"ArrayBuffer"})}),"\n",(0,i.jsx)(r.h4,{id:"throw",children:"Throw"}),"\n",(0,i.jsx)(r.p,{children:"Throws RangeError if list of decoded items is empty"}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"decodewithheaders",children:"decodeWithHeaders()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"decodeWithHeaders"}),"(",(0,i.jsx)(r.code,{children:"pem"}),"): ",(0,i.jsx)(r.a,{href:"/x509/docs/api/interfaces/PemStruct",children:(0,i.jsx)(r.code,{children:"PemStruct"})}),"[]"]}),"\n"]}),"\n",(0,i.jsx)(r.h4,{id:"parameters-2",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"pem-2",children:"pem"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.h4,{id:"returns-3",children:"Returns"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.a,{href:"/x509/docs/api/interfaces/PemStruct",children:(0,i.jsx)(r.code,{children:"PemStruct"})}),"[]"]}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"encode",children:"encode()"}),"\n",(0,i.jsx)(r.h4,{id:"call-signature",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"encode"}),"(",(0,i.jsx)(r.code,{children:"structs"}),"): ",(0,i.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Encodes a list of PemStruct in PEM format"}),"\n",(0,i.jsx)(r.h5,{id:"parameters-3",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"structs",children:"structs"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.a,{href:"/x509/docs/api/#pemstructencodeparams",children:(0,i.jsx)(r.code,{children:"PemStructEncodeParams"})}),"[]"]}),"\n",(0,i.jsx)(r.p,{children:"A list of PemStruct"}),"\n",(0,i.jsx)(r.h5,{id:"returns-4",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.h4,{id:"call-signature-1",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"encode"}),"(",(0,i.jsx)(r.code,{children:"rawData"}),", ",(0,i.jsx)(r.code,{children:"tag"}),"): ",(0,i.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Encodes a raw data in PEM format"}),"\n",(0,i.jsx)(r.h5,{id:"parameters-4",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"rawdata",children:"rawData"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"BufferSource"})}),"\n",(0,i.jsx)(r.p,{children:"Raw data"}),"\n",(0,i.jsx)(r.h6,{id:"tag",children:"tag"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.p,{children:"PEM tag"}),"\n",(0,i.jsx)(r.h5,{id:"returns-5",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.h4,{id:"call-signature-2",children:"Call Signature"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"encode"}),"(",(0,i.jsx)(r.code,{children:"rawData"}),", ",(0,i.jsx)(r.code,{children:"tag"}),"): ",(0,i.jsx)(r.code,{children:"string"})]}),"\n"]}),"\n",(0,i.jsx)(r.p,{children:"Encodes a list of raws in PEM format"}),"\n",(0,i.jsx)(r.h5,{id:"parameters-5",children:"Parameters"}),"\n",(0,i.jsx)(r.h6,{id:"rawdata-1",children:"rawData"}),"\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"BufferSource"}),"[]"]}),"\n",(0,i.jsx)(r.h6,{id:"tag-1",children:"tag"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.p,{children:"PEM tag"}),"\n",(0,i.jsx)(r.h5,{id:"returns-6",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"string"})}),"\n",(0,i.jsx)(r.hr,{}),"\n",(0,i.jsx)(r.h3,{id:"ispem",children:"isPem()"}),"\n",(0,i.jsxs)(r.blockquote,{children:["\n",(0,i.jsxs)(r.p,{children:[(0,i.jsx)(r.code,{children:"static"})," ",(0,i.jsx)(r.strong,{children:"isPem"}),"(",(0,i.jsx)(r.code,{children:"data"}),"): ",(0,i.jsx)(r.code,{children:"data is string"})]}),"\n"]}),"\n",(0,i.jsx)(r.h4,{id:"parameters-6",children:"Parameters"}),"\n",(0,i.jsx)(r.h5,{id:"data",children:"data"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"any"})}),"\n",(0,i.jsx)(r.h4,{id:"returns-7",children:"Returns"}),"\n",(0,i.jsx)(r.p,{children:(0,i.jsx)(r.code,{children:"data is string"})})]})}function o(e={}){const{wrapper:r}={...(0,d.R)(),...e.components};return r?(0,i.jsx)(r,{...e,children:(0,i.jsx)(h,{...e})}):h(e)}},8453:(e,r,s)=>{s.d(r,{R:()=>c,x:()=>l});var n=s(6540);const i={},d=n.createContext(i);function c(e){const r=n.useContext(d);return n.useMemo((function(){return"function"==typeof e?e(r):{...r,...e}}),[r,e])}function l(e){let r;return r=e.disableParentContext?"function"==typeof e.components?e.components(i):e.components||i:c(e.components),n.createElement(d.Provider,{value:r},e.children)}}}]);