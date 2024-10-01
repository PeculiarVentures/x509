"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[1454],{5027:(e,n,r)=>{r.r(n),r.d(n,{assets:()=>o,contentTitle:()=>a,default:()=>h,frontMatter:()=>s,metadata:()=>c,toc:()=>l});var i=r(4848),t=r(8453);const s={},a="X509CertificateCreateParamsBase",c={id:"api/interfaces/X509CertificateCreateParamsBase",title:"X509CertificateCreateParamsBase",description:"Base arguments for certificate creation",source:"@site/docs/api/interfaces/X509CertificateCreateParamsBase.md",sourceDirName:"api/interfaces",slug:"/api/interfaces/X509CertificateCreateParamsBase",permalink:"/x509/docs/api/interfaces/X509CertificateCreateParamsBase",draft:!1,unlisted:!1,tags:[],version:"current",frontMatter:{},sidebar:"docs",previous:{title:"X509CertificateCreateCommonParams",permalink:"/x509/docs/api/interfaces/X509CertificateCreateCommonParams"},next:{title:"X509CertificateCreateSelfSignedParams",permalink:"/x509/docs/api/interfaces/X509CertificateCreateSelfSignedParams"}},o={},l=[{value:"Extended by",id:"extended-by",level:2},{value:"Properties",id:"properties",level:2},{value:"extensions?",id:"extensions",level:3},{value:"notAfter?",id:"notafter",level:3},{value:"notBefore?",id:"notbefore",level:3},{value:"serialNumber?",id:"serialnumber",level:3},{value:"signingAlgorithm?",id:"signingalgorithm",level:3}];function d(e){const n={a:"a",blockquote:"blockquote",code:"code",h1:"h1",h2:"h2",h3:"h3",header:"header",hr:"hr",li:"li",p:"p",strong:"strong",ul:"ul",...(0,t.R)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsx)(n.header,{children:(0,i.jsx)(n.h1,{id:"x509certificatecreateparamsbase",children:"X509CertificateCreateParamsBase"})}),"\n",(0,i.jsx)(n.p,{children:"Base arguments for certificate creation"}),"\n",(0,i.jsx)(n.h2,{id:"extended-by",children:"Extended by"}),"\n",(0,i.jsxs)(n.ul,{children:["\n",(0,i.jsx)(n.li,{children:(0,i.jsx)(n.a,{href:"/x509/docs/api/interfaces/X509CertificateCreateCommonParams",children:(0,i.jsx)(n.code,{children:"X509CertificateCreateCommonParams"})})}),"\n",(0,i.jsx)(n.li,{children:(0,i.jsx)(n.a,{href:"/x509/docs/api/interfaces/X509CertificateCreateSelfSignedParams",children:(0,i.jsx)(n.code,{children:"X509CertificateCreateSelfSignedParams"})})}),"\n"]}),"\n",(0,i.jsx)(n.h2,{id:"properties",children:"Properties"}),"\n",(0,i.jsx)(n.h3,{id:"extensions",children:"extensions?"}),"\n",(0,i.jsxs)(n.blockquote,{children:["\n",(0,i.jsxs)(n.p,{children:[(0,i.jsx)(n.code,{children:"optional"})," ",(0,i.jsx)(n.strong,{children:"extensions"}),": ",(0,i.jsx)(n.a,{href:"/x509/docs/api/classes/Extension",children:(0,i.jsx)(n.code,{children:"Extension"})}),"[]"]}),"\n"]}),"\n",(0,i.jsx)(n.p,{children:"List of extensions"}),"\n",(0,i.jsx)(n.hr,{}),"\n",(0,i.jsx)(n.h3,{id:"notafter",children:"notAfter?"}),"\n",(0,i.jsxs)(n.blockquote,{children:["\n",(0,i.jsxs)(n.p,{children:[(0,i.jsx)(n.code,{children:"optional"})," ",(0,i.jsx)(n.strong,{children:"notAfter"}),": ",(0,i.jsx)(n.code,{children:"Date"})]}),"\n"]}),"\n",(0,i.jsx)(n.p,{children:"Date after which certificate can't be used. Default is 1 year from now"}),"\n",(0,i.jsx)(n.hr,{}),"\n",(0,i.jsx)(n.h3,{id:"notbefore",children:"notBefore?"}),"\n",(0,i.jsxs)(n.blockquote,{children:["\n",(0,i.jsxs)(n.p,{children:[(0,i.jsx)(n.code,{children:"optional"})," ",(0,i.jsx)(n.strong,{children:"notBefore"}),": ",(0,i.jsx)(n.code,{children:"Date"})]}),"\n"]}),"\n",(0,i.jsx)(n.p,{children:"Date before which certificate can't be used. Default is current date"}),"\n",(0,i.jsx)(n.hr,{}),"\n",(0,i.jsx)(n.h3,{id:"serialnumber",children:"serialNumber?"}),"\n",(0,i.jsxs)(n.blockquote,{children:["\n",(0,i.jsxs)(n.p,{children:[(0,i.jsx)(n.code,{children:"optional"})," ",(0,i.jsx)(n.strong,{children:"serialNumber"}),": ",(0,i.jsx)(n.code,{children:"string"})]}),"\n"]}),"\n",(0,i.jsx)(n.p,{children:"Hexadecimal serial number. If not specified, random value will be generated"}),"\n",(0,i.jsx)(n.hr,{}),"\n",(0,i.jsx)(n.h3,{id:"signingalgorithm",children:"signingAlgorithm?"}),"\n",(0,i.jsxs)(n.blockquote,{children:["\n",(0,i.jsxs)(n.p,{children:[(0,i.jsx)(n.code,{children:"optional"})," ",(0,i.jsx)(n.strong,{children:"signingAlgorithm"}),": ",(0,i.jsx)(n.code,{children:"Algorithm"})," | ",(0,i.jsx)(n.code,{children:"EcdsaParams"})]}),"\n"]}),"\n",(0,i.jsx)(n.p,{children:"Signing algorithm. Default is SHA-256 with key algorithm"})]})}function h(e={}){const{wrapper:n}={...(0,t.R)(),...e.components};return n?(0,i.jsx)(n,{...e,children:(0,i.jsx)(d,{...e})}):d(e)}},8453:(e,n,r)=>{r.d(n,{R:()=>a,x:()=>c});var i=r(6540);const t={},s=i.createContext(t);function a(e){const n=i.useContext(s);return i.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function c(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(t):e.components||t:a(e.components),i.createElement(s.Provider,{value:n},e.children)}}}]);