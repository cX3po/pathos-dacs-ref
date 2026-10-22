#!/usr/bin/env bun
import {constants} from 'node:fs';
import {open,readFile,readdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {homedir} from 'node:os';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {execFileSync,spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
export const DEFAULT_SUBJECT='did:demos:agent:6bb11b21d18ba9bb03c4c50085326da4d2192c0cfbb6b575cc42d6dcddc0cda2';
const MAX_BODY=262144;
const fields={json:'successJsonPath',html:'successSelector',xml:'successXPath',raw:'matcher'};
const predicates={json:'jsonPath',html:'selector',xml:'xPath',raw:'matcher'};
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const expr=x=>typeof x==='string'&&x.length>0&&Buffer.byteLength(x)<=4096;
const hash=x=>createHash('sha256').update(x).digest('hex');
export function validateSpec(s){
 if(!plain(s)||!Object.hasOwn(fields,s.format))throw Error('invalid-spec');
 const allowed=['format',fields[s.format],'indeterminateOn',...(s.format==='raw'?[]:['dataMap'])];
 if(Object.keys(s).some(k=>!allowed.includes(k))||!expr(s[fields[s.format]]))throw Error('invalid-spec');
 if(Object.hasOwn(s,'indeterminateOn')&&(!Array.isArray(s.indeterminateOn)||s.indeterminateOn.length>32||s.indeterminateOn.some(p=>!plain(p)||Object.keys(p).length!==1||!expr(p[predicates[s.format]]))))throw Error('invalid-spec');
 if(Object.hasOwn(s,'dataMap')&&(!plain(s.dataMap)||Object.keys(s.dataMap).length>32||Object.entries(s.dataMap).some(([k,v])=>k.length>128||!expr(v))))throw Error('invalid-spec');
 return s;
}
export async function boundedFile(path,max){
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const st=await f.stat();if(!st.isFile()||st.size>max)throw Error('invalid-file');
 const b=Buffer.alloc(max+1);let n=0;while(n<b.length){const r=await f.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}
 if(n>max)throw Error('invalid-file');return new TextDecoder('utf-8',{fatal:true}).decode(b.subarray(0,n));
 }finally{await f.close();}
}
export function endpoint(v='https://node2.demos.sh'){
 if(!['https://node2.demos.sh','https://node2.demos.sh/','https://demosnode.discus.sh','https://demosnode.discus.sh/'].includes(v))throw Error('testnet-only');return new URL(v).origin;
}
export function subject(v){if(typeof v!=='string'||!/^did:demos:agent:[0-9a-f]{64}$/.test(v))throw Error('invalid-subject');return v;}
const sdkRoot=()=>resolve(process.env.DACS_SDK_ROOT||join(process.env.SNAP_REAL_HOME||homedir(),'dacs-sdk'));
export async function loadSdk(){return import(pathToFileURL(join(sdkRoot(),'dist/index.js')).href);}
export async function provenance(){
 const root=sdkRoot(),entries=[];
 async function walk(d){for(const f of(await readdir(d,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){const p=join(d,f.name);if(f.isDirectory())await walk(p);else if(f.isFile()&&f.name.endsWith('.js'))entries.push([p.slice(root.length+1),hash(await readFile(p))]);}}
 await walk(join(root,'dist'));return{gitHead:execFileSync('git',['-C',root,'rev-parse','HEAD'],{encoding:'utf8',timeout:3000}).trim(),runtimeJsFiles:entries.length,runtimeManifestHash:hash(JSON.stringify(entries)),packageLockHash:hash(await readFile(join(root,'package-lock.json')))};
}
export function evaluate(sdk,spec,body,ctx={}){
 validateSpec(spec);if(typeof body!=='string'||Buffer.byteLength(body)>MAX_BODY)throw Error('body-too-large');
 if(!plain(ctx)||Object.keys(ctx).some(k=>!['negativeMatch','listComplete'].includes(k))||Object.values(ctx).some(v=>typeof v!=='boolean'))throw Error('invalid-context');
 return sdk.evaluateParserSpec(spec,body,sdk.defaultParserEngine,ctx);
}
export async function liveDemo(sdk,{rpc='https://node2.demos.sh',did=DEFAULT_SUBJECT,readIdentity}={}){
 rpc=endpoint(rpc);did=subject(did);
 // Wallet omitted. This is a public RPC observation, not authenticated CCI.
 const r=readIdentity?await readIdentity(rpc,did):await(await sdk.createAgent({demosRpc:rpc})).resolveIdentity(did);
 if(!r||r.primaryClaim!==did||!Array.isArray(r.claims)||r.claims.length>256)throw Error('identity-mismatch');
 const body=JSON.stringify({primaryClaim:r.primaryClaim,claims:r.claims.map(c=>({kind:c.kind,ref:c.ref}))});
 const specs=[
 ['primary-claim-present',{format:'json',successJsonPath:'$.primaryClaim',dataMap:{primaryClaim:'$.primaryClaim'}},{}],
 ['missing-field',{format:'json',successJsonPath:'$.__demosspeedAbsent'},{}],
 ['absence-without-completeness',{format:'json',successJsonPath:'$.__demosspeedAbsent'},{negativeMatch:true}],
 ['linked-claim-presence',{format:'json',successJsonPath:'$.claims[*]'},{}]];
 return{schema:'demosspeed-recipe-demo-v1',observedAt:new Date().toISOString(),rpc,subject:did,trust:'unverified RPC observation; unsigned local recipe evaluation',bodyHash:hash(body),linkedClaims:r.claims.length,engine:sdk.defaultParserEngineCapabilities,cases:specs.map(([name,s,c])=>({name,...evaluate(sdk,s,body,c)}))};
}
function options(args,allowed){const o={};for(let i=0;i<args.length;i++){const k=args[i];if(!allowed.includes(k)||Object.hasOwn(o,k))throw Error('usage');if(['--negative-match','--list-complete'].includes(k))o[k]=true;else{if(!args[i+1]||args[i+1].startsWith('--'))throw Error('usage');o[k]=args[++i];}}return o;}
export function demoExitCode(result){return Array.isArray(result?.cases)&&result.cases.length>0&&result.cases.every(c=>['pass','fail','indeterminate'].includes(c.decision))?0:2;}
export async function main(args=process.argv.slice(2)){
 const cmd=args.shift();if(['--help','help'].includes(cmd)){console.log('bun main.mjs evaluate --spec SPEC.json --body BODY [--negative-match] [--list-complete]\nbun main.mjs demo [--rpc https://node2.demos.sh] [--subject did:demos:agent:<hex>]');return 0;}
 if(!['evaluate','demo'].includes(cmd))throw Error('usage');
 const o=options(args,cmd==='demo'?['--rpc','--subject']:['--spec','--body','--negative-match','--list-complete']);
 if(cmd==='demo'){endpoint(o['--rpc']);subject(o['--subject']||DEFAULT_SUBJECT);}else if(!o['--spec']||!o['--body'])throw Error('usage');
 const sdk=await loadSdk();
 const result=cmd==='demo'?await liveDemo(sdk,{rpc:o['--rpc'],did:o['--subject']||DEFAULT_SUBJECT}):{schema:'demosspeed-recipe-evaluation-v1',trust:'unsigned local experiment; completeness is a caller assertion, not authenticated proof',evaluation:evaluate(sdk,JSON.parse(await boundedFile(o['--spec'],16384)),await boundedFile(o['--body'],MAX_BODY),{negativeMatch:!!o['--negative-match'],listComplete:!!o['--list-complete']})};
 result.sdk=await provenance();console.log(JSON.stringify(result,null,2));return cmd==='demo'?demoExitCode(result):({pass:0,fail:1,error:2,indeterminate:3}[result.evaluation.decision]??2);
}
export function runIsolated(args,{timeoutMs=20000}={}){
 if(!Array.isArray(args)||args.some(a=>typeof a!=='string')||Buffer.byteLength(JSON.stringify(args))>16384||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>20000)throw Error('usage');
 return new Promise((done,reject)=>{
  const child=spawn(process.execPath,[fileURLToPath(new URL('./worker.mjs',import.meta.url)),...args],{stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='',timedOut=false,oversized=false;
  const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},timeoutMs);
  child.stdout.on('data',b=>{stdout+=b;if(Buffer.byteLength(stdout)>1048576){oversized=true;child.kill('SIGKILL');}});
  child.stderr.on('data',b=>{stderr=(stderr+b).slice(0,4096);});
  child.on('error',()=>{clearTimeout(timer);reject(Error('worker-failed'));});
  child.on('close',code=>{clearTimeout(timer);done({code:timedOut||oversized?2:(code??2),stdout:timedOut||oversized?'':stdout,stderr:timedOut?'recipe-studio: deadline\n':oversized?'recipe-studio: output limit\n':stderr,timedOut});});
 });
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 try{const r=await runIsolated(process.argv.slice(2));process.stdout.write(r.stdout);process.stderr.write(r.stderr);process.exit(r.code);}
 catch{console.error('recipe-studio: invalid input or worker failed');process.exit(2);}
}
