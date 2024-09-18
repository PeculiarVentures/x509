"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[6301],{339:(e,n,s)=>{s.r(n),s.d(n,{assets:()=>l,contentTitle:()=>d,default:()=>o,frontMatter:()=>c,metadata:()=>i,toc:()=>a});var r=s(4848),t=s(8453);const c={},d="abstract AsnData<T>",i={id:"api/classes/AsnData",title:"abstract AsnData\\<T\\>",description:"Represents an ASN.1 data",source:"@site/docs/api/classes/AsnData.md",sourceDirName:"api/classes",slug:"/api/classes/AsnData",permalink:"/x509/docs/api/classes/AsnData",draft:!1,unlisted:!1,tags:[],version:"current",frontMatter:{},sidebar:"docs",previous:{title:"AlgorithmProvider",permalink:"/x509/docs/api/classes/AlgorithmProvider"},next:{title:"AsnDefaultSignatureFormatter",permalink:"/x509/docs/api/classes/AsnDefaultSignatureFormatter"}},l={},a=[{value:"Extended by",id:"extended-by",level:2},{value:"Type Parameters",id:"type-parameters",level:2},{value:"Implements",id:"implements",level:2},{value:"Constructors",id:"constructors",level:2},{value:"new AsnData()",id:"new-asndata",level:3},{value:"Parameters",id:"parameters",level:4},{value:"Returns",id:"returns",level:4},{value:"new AsnData()",id:"new-asndata-1",level:3},{value:"Parameters",id:"parameters-1",level:4},{value:"Returns",id:"returns-1",level:4},{value:"Properties",id:"properties",level:2},{value:"rawData",id:"rawdata",level:3},{value:"NAME",id:"name",level:3},{value:"Methods",id:"methods",level:2},{value:"equal()",id:"equal",level:3},{value:"Parameters",id:"parameters-2",level:4},{value:"Returns",id:"returns-2",level:4},{value:"getTextName()",id:"gettextname",level:3},{value:"Returns",id:"returns-3",level:4},{value:"onInit()",id:"oninit",level:3},{value:"Parameters",id:"parameters-3",level:4},{value:"Returns",id:"returns-4",level:4},{value:"toString()",id:"tostring",level:3},{value:"Parameters",id:"parameters-4",level:4},{value:"Returns",id:"returns-5",level:4},{value:"toTextObject()",id:"totextobject",level:3},{value:"Returns",id:"returns-6",level:4},{value:"Implementation of",id:"implementation-of",level:4},{value:"toTextObjectEmpty()",id:"totextobjectempty",level:3},{value:"Parameters",id:"parameters-5",level:4},{value:"Returns",id:"returns-7",level:4}];function h(e){const n={a:"a",blockquote:"blockquote",code:"code",h1:"h1",h2:"h2",h3:"h3",h4:"h4",header:"header",hr:"hr",li:"li",p:"p",strong:"strong",ul:"ul",...(0,t.R)(),...e.components};return(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(n.header,{children:(0,r.jsxs)(n.h1,{id:"abstract-asndatat",children:[(0,r.jsx)(n.code,{children:"abstract"})," AsnData<T>"]})}),"\n",(0,r.jsx)(n.p,{children:"Represents an ASN.1 data"}),"\n",(0,r.jsx)(n.h2,{id:"extended-by",children:"Extended by"}),"\n",(0,r.jsxs)(n.ul,{children:["\n",(0,r.jsx)(n.li,{children:(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/Attribute",children:(0,r.jsx)(n.code,{children:"Attribute"})})}),"\n",(0,r.jsx)(n.li,{children:(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/Extension",children:(0,r.jsx)(n.code,{children:"Extension"})})}),"\n",(0,r.jsx)(n.li,{children:(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/X509CrlEntry",children:(0,r.jsx)(n.code,{children:"X509CrlEntry"})})}),"\n",(0,r.jsx)(n.li,{children:(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/GeneralName",children:(0,r.jsx)(n.code,{children:"GeneralName"})})}),"\n",(0,r.jsx)(n.li,{children:(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/GeneralNames",children:(0,r.jsx)(n.code,{children:"GeneralNames"})})}),"\n"]}),"\n",(0,r.jsx)(n.h2,{id:"type-parameters",children:"Type Parameters"}),"\n",(0,r.jsxs)(n.p,{children:["\u2022 ",(0,r.jsx)(n.strong,{children:"T"})]}),"\n",(0,r.jsx)(n.h2,{id:"implements",children:"Implements"}),"\n",(0,r.jsxs)(n.ul,{children:["\n",(0,r.jsx)(n.li,{children:(0,r.jsx)(n.a,{href:"/x509/docs/api/interfaces/TextObjectConvertible",children:(0,r.jsx)(n.code,{children:"TextObjectConvertible"})})}),"\n"]}),"\n",(0,r.jsx)(n.h2,{id:"constructors",children:"Constructors"}),"\n",(0,r.jsx)(n.h3,{id:"new-asndata",children:"new AsnData()"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.strong,{children:"new AsnData"}),"<",(0,r.jsx)(n.code,{children:"T"}),">(",(0,r.jsx)(n.code,{children:"raw"}),", ",(0,r.jsx)(n.code,{children:"type"}),"): ",(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/AsnData",children:(0,r.jsx)(n.code,{children:"AsnData"})}),"<",(0,r.jsx)(n.code,{children:"T"}),">"]}),"\n"]}),"\n",(0,r.jsx)(n.p,{children:"Creates a new instance"}),"\n",(0,r.jsx)(n.h4,{id:"parameters",children:"Parameters"}),"\n",(0,r.jsxs)(n.p,{children:["\u2022 ",(0,r.jsx)(n.strong,{children:"raw"}),": ",(0,r.jsx)(n.code,{children:"BufferSource"})]}),"\n",(0,r.jsx)(n.p,{children:"DER encoded buffer"}),"\n",(0,r.jsxs)(n.p,{children:["\u2022 ",(0,r.jsx)(n.strong,{children:"type"})]}),"\n",(0,r.jsxs)(n.p,{children:["ASN.1 convertible class for ",(0,r.jsx)(n.code,{children:"@peculiar/asn1-schema"})," schema"]}),"\n",(0,r.jsx)(n.h4,{id:"returns",children:"Returns"}),"\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/AsnData",children:(0,r.jsx)(n.code,{children:"AsnData"})}),"<",(0,r.jsx)(n.code,{children:"T"}),">"]}),"\n",(0,r.jsx)(n.h3,{id:"new-asndata-1",children:"new AsnData()"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.strong,{children:"new AsnData"}),"<",(0,r.jsx)(n.code,{children:"T"}),">(",(0,r.jsx)(n.code,{children:"asn"}),"): ",(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/AsnData",children:(0,r.jsx)(n.code,{children:"AsnData"})}),"<",(0,r.jsx)(n.code,{children:"T"}),">"]}),"\n"]}),"\n",(0,r.jsx)(n.p,{children:"ASN.1 object"}),"\n",(0,r.jsx)(n.h4,{id:"parameters-1",children:"Parameters"}),"\n",(0,r.jsxs)(n.p,{children:["\u2022 ",(0,r.jsx)(n.strong,{children:"asn"}),": ",(0,r.jsx)(n.code,{children:"T"})]}),"\n",(0,r.jsx)(n.h4,{id:"returns-1",children:"Returns"}),"\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/AsnData",children:(0,r.jsx)(n.code,{children:"AsnData"})}),"<",(0,r.jsx)(n.code,{children:"T"}),">"]}),"\n",(0,r.jsx)(n.h2,{id:"properties",children:"Properties"}),"\n",(0,r.jsx)(n.h3,{id:"rawdata",children:"rawData"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.code,{children:"readonly"})," ",(0,r.jsx)(n.strong,{children:"rawData"}),": ",(0,r.jsx)(n.code,{children:"ArrayBuffer"})]}),"\n"]}),"\n",(0,r.jsx)(n.p,{children:"Gets a DER encoded buffer"}),"\n",(0,r.jsx)(n.hr,{}),"\n",(0,r.jsx)(n.h3,{id:"name",children:"NAME"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.code,{children:"static"})," ",(0,r.jsx)(n.strong,{children:"NAME"}),": ",(0,r.jsx)(n.code,{children:"string"})," = ",(0,r.jsx)(n.code,{children:'"ASN"'})]}),"\n"]}),"\n",(0,r.jsx)(n.h2,{id:"methods",children:"Methods"}),"\n",(0,r.jsx)(n.h3,{id:"equal",children:"equal()"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.strong,{children:"equal"}),"(",(0,r.jsx)(n.code,{children:"data"}),"): ",(0,r.jsx)(n.code,{children:"data is AsnData<T>"})]}),"\n"]}),"\n",(0,r.jsxs)(n.p,{children:["Returns ",(0,r.jsx)(n.code,{children:"true"})," if ASN.1 data is equal to another ASN.1 data, otherwise ",(0,r.jsx)(n.code,{children:"false"})]}),"\n",(0,r.jsx)(n.h4,{id:"parameters-2",children:"Parameters"}),"\n",(0,r.jsxs)(n.p,{children:["\u2022 ",(0,r.jsx)(n.strong,{children:"data"}),": ",(0,r.jsx)(n.code,{children:"any"})]}),"\n",(0,r.jsx)(n.p,{children:"Any data"}),"\n",(0,r.jsx)(n.h4,{id:"returns-2",children:"Returns"}),"\n",(0,r.jsx)(n.p,{children:(0,r.jsx)(n.code,{children:"data is AsnData<T>"})}),"\n",(0,r.jsx)(n.hr,{}),"\n",(0,r.jsx)(n.h3,{id:"gettextname",children:"getTextName()"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.code,{children:"protected"})," ",(0,r.jsx)(n.strong,{children:"getTextName"}),"(): ",(0,r.jsx)(n.code,{children:"string"})]}),"\n"]}),"\n",(0,r.jsx)(n.h4,{id:"returns-3",children:"Returns"}),"\n",(0,r.jsx)(n.p,{children:(0,r.jsx)(n.code,{children:"string"})}),"\n",(0,r.jsx)(n.hr,{}),"\n",(0,r.jsx)(n.h3,{id:"oninit",children:"onInit()"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.code,{children:"abstract"})," ",(0,r.jsx)(n.code,{children:"protected"})," ",(0,r.jsx)(n.strong,{children:"onInit"}),"(",(0,r.jsx)(n.code,{children:"asn"}),"): ",(0,r.jsx)(n.code,{children:"void"})]}),"\n"]}),"\n",(0,r.jsx)(n.p,{children:"Occurs on instance initialization"}),"\n",(0,r.jsx)(n.h4,{id:"parameters-3",children:"Parameters"}),"\n",(0,r.jsxs)(n.p,{children:["\u2022 ",(0,r.jsx)(n.strong,{children:"asn"}),": ",(0,r.jsx)(n.code,{children:"T"})]}),"\n",(0,r.jsx)(n.p,{children:"ASN.1 object"}),"\n",(0,r.jsx)(n.h4,{id:"returns-4",children:"Returns"}),"\n",(0,r.jsx)(n.p,{children:(0,r.jsx)(n.code,{children:"void"})}),"\n",(0,r.jsx)(n.hr,{}),"\n",(0,r.jsx)(n.h3,{id:"tostring",children:"toString()"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.strong,{children:"toString"}),"(",(0,r.jsx)(n.code,{children:"format"}),"): ",(0,r.jsx)(n.code,{children:"string"})]}),"\n"]}),"\n",(0,r.jsx)(n.p,{children:"Returns a string representation of an object."}),"\n",(0,r.jsx)(n.h4,{id:"parameters-4",children:"Parameters"}),"\n",(0,r.jsxs)(n.p,{children:["\u2022 ",(0,r.jsx)(n.strong,{children:"format"}),": ",(0,r.jsx)(n.a,{href:"/x509/docs/api/#asndatastringformat",children:(0,r.jsx)(n.code,{children:"AsnDataStringFormat"})})," = ",(0,r.jsx)(n.code,{children:'"text"'})]}),"\n",(0,r.jsx)(n.h4,{id:"returns-5",children:"Returns"}),"\n",(0,r.jsx)(n.p,{children:(0,r.jsx)(n.code,{children:"string"})}),"\n",(0,r.jsx)(n.hr,{}),"\n",(0,r.jsx)(n.h3,{id:"totextobject",children:"toTextObject()"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.strong,{children:"toTextObject"}),"(): ",(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/TextObject",children:(0,r.jsx)(n.code,{children:"TextObject"})})]}),"\n"]}),"\n",(0,r.jsx)(n.p,{children:"Returns the object in textual representation"}),"\n",(0,r.jsx)(n.h4,{id:"returns-6",children:"Returns"}),"\n",(0,r.jsx)(n.p,{children:(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/TextObject",children:(0,r.jsx)(n.code,{children:"TextObject"})})}),"\n",(0,r.jsx)(n.h4,{id:"implementation-of",children:"Implementation of"}),"\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.a,{href:"/x509/docs/api/interfaces/TextObjectConvertible",children:(0,r.jsx)(n.code,{children:"TextObjectConvertible"})}),".",(0,r.jsx)(n.a,{href:"/x509/docs/api/interfaces/TextObjectConvertible#totextobject",children:(0,r.jsx)(n.code,{children:"toTextObject"})})]}),"\n",(0,r.jsx)(n.hr,{}),"\n",(0,r.jsx)(n.h3,{id:"totextobjectempty",children:"toTextObjectEmpty()"}),"\n",(0,r.jsxs)(n.blockquote,{children:["\n",(0,r.jsxs)(n.p,{children:[(0,r.jsx)(n.code,{children:"protected"})," ",(0,r.jsx)(n.strong,{children:"toTextObjectEmpty"}),"(",(0,r.jsx)(n.code,{children:"value"}),"?): ",(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/TextObject",children:(0,r.jsx)(n.code,{children:"TextObject"})})]}),"\n"]}),"\n",(0,r.jsx)(n.h4,{id:"parameters-5",children:"Parameters"}),"\n",(0,r.jsxs)(n.p,{children:["\u2022 ",(0,r.jsx)(n.strong,{children:"value?"}),": ",(0,r.jsx)(n.code,{children:"string"})]}),"\n",(0,r.jsx)(n.h4,{id:"returns-7",children:"Returns"}),"\n",(0,r.jsx)(n.p,{children:(0,r.jsx)(n.a,{href:"/x509/docs/api/classes/TextObject",children:(0,r.jsx)(n.code,{children:"TextObject"})})})]})}function o(e={}){const{wrapper:n}={...(0,t.R)(),...e.components};return n?(0,r.jsx)(n,{...e,children:(0,r.jsx)(h,{...e})}):h(e)}},8453:(e,n,s)=>{s.d(n,{R:()=>d,x:()=>i});var r=s(6540);const t={},c=r.createContext(t);function d(e){const n=r.useContext(c);return r.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function i(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(t):e.components||t:d(e.components),r.createElement(c.Provider,{value:n},e.children)}}}]);