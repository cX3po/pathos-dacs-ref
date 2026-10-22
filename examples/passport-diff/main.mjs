#!/usr/bin/env bun
import {readFile,stat} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {userInfo} from 'node:os';
import {resolve} from 'node:path';
export const LIMIT=262144;
const KINDS=new Set(['web2','wallet','ud','pqc','nomis','humanpassport','ethos','tlsn']);
const CLAIM_KEYS=new Set(['kind','ref','score','observedAt','expiresAt','passingScore','threshold']);
const SNAP_KEYS=['schema','subject','endpoint','observedAt','sdkCommit','trust','claims','contentHash'];
function insist(ok){if(!ok)throw new Error('invalid input');}
function plain(x){return x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function exact(x,keys){insist(plain(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k)));}
export function endpoint(value){insist(typeof value==='string'&&['https://node2.demos.sh','https://demosnode.discus.sh'].includes(value));return value;}
export function subject(value,sdk){
 insist(typeof value==='string'&&value.length<=80);
 const did=/^(?:0x)?[0-9a-f]{64}$/.test(value)?`did:demos:agent:${value.replace(/^0x/,'')}`:value;
 const parsed=sdk.parseDemosAgentClaimReference(did);
 insist(parsed&&parsed.canonicalIdentity===did&&parsed.canonicalReference===did);return did;
}
export async function loadSdk(root=process.env.DACS_SDK_ROOT||resolve(process.env.SNAP_REAL_HOME || userInfo().homedir,'dacs-sdk')){
 const sdk=await import(pathToFileURL(resolve(root,'dist/index.js')).href);
 const gitPath=resolve(root,'.git');
 const gitInfo=await stat(gitPath);
 const gitDir=gitInfo.isDirectory()?gitPath:resolve(root,(await readFile(gitPath,'utf8')).trim().replace(/^gitdir: /,''));
 const head=(await readFile(resolve(gitDir,'HEAD'),'utf8')).trim();
 let sdkCommit=head;
 if(head.startsWith('ref: ')){
  const ref=head.slice(5);insist(/^refs\/[A-Za-z0-9_./-]+$/.test(ref)&&!ref.includes('..'));
  try{sdkCommit=(await readFile(resolve(gitDir,ref),'utf8')).trim();}
  catch{const packed=await readFile(resolve(gitDir,'packed-refs'),'utf8');sdkCommit=packed.split('\n').find(line=>line.endsWith(' '+ref))?.split(' ')[0];}
 }
 insist(/^[0-9a-f]{40}$/.test(sdkCommit));return{sdk,sdkCommit};
}
function projectClaims(claims,sdk,strict=false){
 insist(Array.isArray(claims)&&claims.length<=256);const seen=new Set();
 return claims.map(c=>{
  insist(plain(c)&&KINDS.has(c.kind)&&typeof c.ref==='string'&&c.ref.length<=2048&&sdk.isCanonicalClaimReference(c.ref)&&!seen.has(c.ref));
  if(strict)insist(Object.keys(c).every(k=>CLAIM_KEYS.has(k)));seen.add(c.ref);
  const out={kind:c.kind,ref:c.ref};
  for(const k of ['score','observedAt','expiresAt','threshold'])if(Object.hasOwn(c,k)){
   insist((k==='expiresAt'&&c[k]===null)||(typeof c[k]==='number'&&Number.isFinite(c[k])&&c[k]>=0));out[k]=c[k];
  }
  if(Object.hasOwn(c,'passingScore')){insist(typeof c.passingScore==='boolean');out.passingScore=c.passingScore;}
  return out;
 }).sort((a,b)=>a.ref<b.ref?-1:a.ref>b.ref?1:0);
}
function digest(s,sdk){const{contentHash,...body}=s;return sdk.sha256Hex(sdk.canonicalize(body));}
export function validateSnapshot(v,sdk){
 exact(v,SNAP_KEYS);insist(v.schema==='demos-passport-observation/v1'&&v.trust==='unverified-rpc-observation');
 insist(subject(v.subject,sdk)===v.subject);endpoint(v.endpoint);
 insist(Number.isSafeInteger(v.observedAt)&&v.observedAt>=0&&/^[0-9a-f]{40}$/.test(v.sdkCommit)&&/^[0-9a-f]{64}$/.test(v.contentHash));
 const claims=projectClaims(v.claims,sdk,true);insist(sdk.canonicalize(claims)===sdk.canonicalize(v.claims));
 insist(digest(v,sdk)===v.contentHash&&Buffer.byteLength(JSON.stringify(v))<=LIMIT);return v;
}
export async function snapshot({subject:input,endpoint:rpc='https://node2.demos.sh',sdk,sdkCommit,read,now=Date.now,timeoutMs=15000}){
 const did=subject(input,sdk);endpoint(rpc);insist(/^[0-9a-f]{40}$/.test(sdkCommit)&&Number.isSafeInteger(timeoutMs)&&timeoutMs>=1&&timeoutMs<=30000);
 let timer;try{
  const record=await Promise.race([Promise.resolve().then(async()=>read?read(did,rpc):(await sdk.createAgent({demosRpc:rpc})).resolveIdentity(did)),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('read deadline exceeded')),timeoutMs);})]);
  insist(plain(record)&&record.primaryClaim===did);
  const v={schema:'demos-passport-observation/v1',subject:did,endpoint:rpc,observedAt:now(),sdkCommit,trust:'unverified-rpc-observation',claims:projectClaims(record.claims,sdk)};
  v.contentHash=digest(v,sdk);return validateSnapshot(v,sdk);
 }finally{clearTimeout(timer);}
}
export function diff(before,after,sdk){
 validateSnapshot(before,sdk);validateSnapshot(after,sdk);insist(before.subject===after.subject&&before.endpoint===after.endpoint);
 const a=new Map(before.claims.map(c=>[c.ref,c]));const b=new Map(after.claims.map(c=>[c.ref,c]));
 return{schema:'demos-passport-diff/v1',subject:before.subject,trust:'unverified-rpc-observation',beforeHash:before.contentHash,afterHash:after.contentHash,added:after.claims.filter(c=>!a.has(c.ref)),removed:before.claims.filter(c=>!b.has(c.ref)),changed:after.claims.filter(c=>a.has(c.ref)&&sdk.canonicalize(a.get(c.ref))!==sdk.canonicalize(c)).map(c=>({ref:c.ref,before:a.get(c.ref),after:c}))};
}
async function readSnapshot(path,sdk){insist(typeof path==='string'&&path.length<=4096);const info=await stat(path);insist(info.isFile()&&info.size<=LIMIT);const bytes=await readFile(path);insist(bytes.length<=LIMIT);return validateSnapshot(JSON.parse(bytes.toString('utf8')),sdk);}
async function main(args){
 const{sdk,sdkCommit}=await loadSdk();let result;
 if(args[0]==='snapshot'&&(args.length===2||args.length===3))result=await snapshot({subject:args[1],endpoint:args[2],sdk,sdkCommit});
 else if(args[0]==='diff'&&args.length===3)result=diff(await readSnapshot(args[1],sdk),await readSnapshot(args[2],sdk),sdk);
 else throw new Error('usage');await new Promise((done,fail)=>process.stdout.write(JSON.stringify(result,null,2)+'\n',error=>error?fail(error):done()));
}
if(import.meta.main){const watchdog=setTimeout(()=>{console.error('passport operation exceeded deadline');process.exit(1);},20000);main(process.argv.slice(2)).then(()=>{clearTimeout(watchdog);process.exit(0);}).catch(()=>{console.error('passport failed: invalid input, SDK configuration, or unavailable testnet read');process.exit(1);});}
