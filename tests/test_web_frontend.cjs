// Dependency-free execution of the real browser controller, including delayed responses.
const {readFileSync} = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(tag='div') { this.tagName=tag.toUpperCase();this.children=[];this.value='';this.open=false;this.listeners={}; }
  append(...children) {this.children.push(...children);}
  replaceChildren(...children) {this.children=children;}
  addEventListener(type,fn) {this.listeners[type]=fn;}
  close() {this.open=false;}
  showModal() {this.open=true;}
  reset() {this.value='';}
  querySelector() {return this.children[0]?.children[0];}
  focus() {}
}
const nodes = new Map();
const doc = {
  getElementById(id) {if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},
  createElement(tag) {return new Element(tag);},addEventListener() {}
};
let account='alice', delayRead=false, resolveRead, requests=[];
const response=data=>({ok:true,json:async()=>data});
const sandbox={document:doc,window:{addEventListener(){}},navigator:{clipboard:{writeText:async()=>{}}},
  confirm:()=>true, console,
  fetch:async(url,options={})=>{
    if(url==='/api/session')return response({sub:account,email:account+'@example.com'});
    requests.push({url,options});
    if(url.endsWith('/secrets/read') && delayRead) return new Promise(resolve=>{resolveRead=resolve;});
    return response({data:[]});
  }};
vm.createContext(sandbox);
vm.runInContext(readFileSync('src/passage_mcp/static/vault.js','utf8'),sandbox);
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
  await flush();await flush();
  assert.equal(doc.getElementById('status').textContent,'Vault ready.');
  assert.ok(requests.every(r=>r.options.headers['X-Passage-Subject']==='alice'));
  // Drafts must disappear and old decrypted responses must be rejected on account switch.
  vm.runInContext("editor('Draft',[{name:'value',label:'Value',value:'private draft'}],()=>{})",sandbox);
  assert.equal(doc.getElementById('editor').open,true);
  delayRead=true;
  const pending=vm.runInContext("api('secrets/read',{folder:'personal',item_name:'login'})",sandbox);
  await flush();assert.equal(typeof resolveRead,'function');
  account='bob';await vm.runInContext('session()',sandbox);
  assert.equal(doc.getElementById('editor').open,false);
  assert.equal(doc.getElementById('fields').children.length,0);
  assert.equal(doc.getElementById('vault').children.length,0);
  assert.equal(doc.getElementById('dialog-title').textContent,'');
  resolveRead(response({data:{password:'alice secret',username:'alice'}}));
  await assert.rejects(pending,/Account changed/);
  // A pre-switch draft cannot issue a mutation to the new account.
  const before=requests.length;
  await assert.rejects(vm.runInContext("api('secrets/update',{folder:'personal',item_name:'login',value:'old draft'},0)",sandbox),/Account changed/);
  assert.equal(requests.length,before);
  // User-controlled names become text nodes, never markup.
  const row=vm.runInContext("secretRow('folder','<img src=x onerror=alert(1)>')",sandbox);
  assert.equal(row.children[0].children[0].textContent,'<img src=x onerror=alert(1)>');
  assert.equal(row.children[0].children[0].children.length,0);
  vm.runInContext("editor('Reveal',[],null)",sandbox);
  assert.equal(doc.getElementById('save').hidden,true);
  assert.equal(doc.getElementById('cancel').textContent,'Close');
  assert.equal(vm.runInContext('submitAction',sandbox),null);
  console.log('Frontend: session binding, stale response rejection, draft clearing, text rendering passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
