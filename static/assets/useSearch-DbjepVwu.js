import{u as e,i as a,F as s}from"./useForm-CaeTx-0K.js";import{d as o,av as t,f as n,z as l,c as i,o as c,F as r,i as d,j as u,w as h,x as m,t as p,a as f,r as w,I as g,aT as b,bO as v,g as y,U as x,J as S,aw as E,bP as F,bQ as L,bN as R,a3 as k}from"./index-B3EiCo2S.js";import{u as j}from"./useIcon-BB0QiO3L.js";const O=o({__name:"ActionButton",props:{showSearch:t.bool.def(!0),showReset:t.bool.def(!0),showExpand:t.bool.def(!1),visible:t.bool.def(!0),searchLoading:t.bool.def(!1),resetLoading:t.bool.def(!1)},emits:["search","reset","expand"],setup(e,{emit:a}){const s=a,{t:o}=n(),t=()=>{s("search")},w=()=>{s("reset")},g=()=>{s("expand")};return(a,s)=>{const n=l("BaseButton");return c(),i(r,null,[e.showSearch?(c(),d(n,{key:0,type:"primary",loading:e.searchLoading,icon:f(j)({icon:"ep:search"}),onClick:t},{default:h((()=>[m(p(f(o)("common.query")),1)])),_:1},8,["loading","icon"])):u("",!0),e.showReset?(c(),d(n,{key:1,loading:e.resetLoading,plain:"",icon:f(j)({icon:"ep:refresh-right"}),onClick:w},{default:h((()=>[m(p(f(o)("common.reset")),1)])),_:1},8,["loading","icon"])):u("",!0),e.showExpand?(c(),d(n,{key:2,icon:f(j)({icon:e.visible?"ep:arrow-up":"ep:arrow-down"}),text:"",onClick:g},{default:h((()=>[m(p(f(o)(e.visible?"common.shrink":"common.expand")),1)])),_:1},8,["icon"])):u("",!0)],64)}}}),V=o({__name:"Search",props:{schema:{type:Array,default:()=>[]},isCol:t.bool.def(!1),labelWidth:t.oneOfType([String,Number]).def("auto"),layout:t.string.validate((e=>["inline","bottom"].includes(e))).def("inline"),buttonPosition:t.string.validate((e=>["left","center","right"].includes(e))).def("center"),showSearch:t.bool.def(!0),showReset:t.bool.def(!0),showExpand:t.bool.def(!1),expandField:t.string.def(""),inline:t.bool.def(!0),removeNoValueItem:t.bool.def(!0),model:{type:Object,default:()=>({})},searchLoading:t.bool.def(!1),resetLoading:t.bool.def(!1)},emits:["search","reset","register","validate"],setup(o,{expose:t,emit:n}){const l=o,d=n,h=w(!0),p=w(l.model),k=g((()=>{const e=f(A);let a=b(e.schema);if(e.showExpand&&e.expandField&&!f(h)){const s=v(a,(a=>a.field===e.expandField));a.map(((e,a)=>(e.hidden=a>=s,e)))}return"inline"===e.layout&&(a=a.concat([{field:"action",formItemProps:{labelWidth:"0px",slots:{default:()=>y("div",null,[y(O,{showSearch:e.showSearch,showReset:e.showReset,showExpand:e.showExpand,searchLoading:e.searchLoading,resetLoading:e.resetLoading,visible:h.value,onExpand:T,onReset:q,onSearch:W},null)]),label:()=>y("span",null,[m(" ")])}}}])),a})),{formRegister:j,formMethods:V}=e(),{getElFormExpose:_,getFormData:P,getFormExpose:C}=V,I=w({}),N=w({}),A=g((()=>{const e={...l};return Object.assign(e,f(N)),e})),B=w([]);x((()=>f(k)),(async(e=[])=>{p.value=a(e,f(p)),B.value=e}),{immediate:!0,deep:!0});const M=async()=>{const e=await P();return f(A).removeNoValueItem?Object.keys(e).reduce(((a,s)=>{const o=e[s];return F(o)||(L(o)?Object.keys(o).length>0&&(a[s]=o):a[s]=o),a}),{}):e},W=async()=>{const e=await _();await(null==e?void 0:e.validate((async e=>{if(e){const e=await M();d("search",e)}})))},q=async()=>{const e=await _();null==e||e.resetFields();const a=await M();d("reset",a)},D=g((()=>({textAlign:f(A).buttonPosition}))),T=async()=>{h.value=!f(h)},z={getElFormExpose:_,setProps:(e={})=>{N.value=Object.assign(f(N),e),I.value=e},setSchema:e=>{const{schema:a}=f(A);for(const s of a)for(const a of e)s.field===a.field&&R(s,a.path,a.value)},setValues:async(e={})=>{p.value=Object.assign(l.model,f(p),e);const a=await C();null==a||a.setValues(e)},delSchema:e=>{const{schema:a}=f(A),s=v(a,(a=>a.field===e));s>-1&&a.splice(s,1)},addSchema:(e,a)=>{const{schema:s}=f(A);void 0===a?s.push(e):s.splice(a,0,e)}};S((()=>{d("register",z)})),t(z);const J=(e,a,s)=>{d("validate",e,a,s)};return(e,a)=>(c(),i(r,null,[y(f(s),{model:p.value,"is-custom":!1,"label-width":A.value.labelWidth,"hide-required-asterisk":"",inline:A.value.inline,"is-col":A.value.isCol,schema:B.value,onRegister:f(j),onValidate:J},null,8,["model","label-width","inline","is-col","schema","onRegister"]),"bottom"===o.layout?(c(),i("div",{key:0,style:E(D.value)},[y(O,{"show-reset":A.value.showReset,"show-search":A.value.showSearch,"show-expand":A.value.showExpand,"search-loading":A.value.searchLoading,"reset-loading":A.value.resetLoading,onExpand:T,onReset:q,onSearch:W},null,8,["show-reset","show-search","show-expand","search-loading","reset-loading"])],4)):u("",!0)],64))}}),_=()=>{const e=w(),a=async()=>{await k();const a=f(e);return a};return{searchRegister:a=>{e.value=a},searchMethods:{setProps:async(e={})=>{const s=await a();null==s||s.setProps(e),e.model&&(null==s||s.setValues(e.model))},setValues:async e=>{const s=await a();null==s||s.setValues(e)},setSchema:async e=>{const s=await a();null==s||s.setSchema(e)},addSchema:async(e,s)=>{const o=await a();null==o||o.addSchema(e,s)},delSchema:async e=>{const s=await a();null==s||s.delSchema(e)},getFormData:async()=>{const e=await a();return null==e?void 0:e.formModel}}}};export{V as _,_ as u};
