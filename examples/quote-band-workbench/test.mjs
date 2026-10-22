import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync,mkdirSync,cpSync,appendFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {inspect,loadSdk} from './cli.mjs';
const sdk = await loadSdk(process.env.DACS_SDK_ROOT);
const pricing = (amount='1.5',minPct=10,maxPct=10) => ({kind:'negotiable',bandCenter:{amount,currency:'DEM'},minPct,maxPct});
const input = (p,amounts=[]) => ({pricing:p,counteroffers:amounts.map(amount=>({amount,currency:'DEM'}))});
const fixtures = [
  ['1.5',10,10,'1.4','1.7'], // ties: 1.35 -> 1.4, 1.65 -> 1.7
  ['1.01',50,50,'0.51','1.52'], // 0.505 and 1.515
  ['15',10,10,'14','17'], // whole-unit ties
  ['1.51',10,10,'1.36','1.66'], // non-ties round down
  ['100',0,0,'100','100'],
  ['900719925474099312345678901234567890.1',0,0,'900719925474099312345678901234567890.1','900719925474099312345678901234567890.1'],
  ['1'+'0'.repeat(999),10,10,'9'+'0'.repeat(998),'11'+'0'.repeat(998)],
];
for (const [centre,min,max,lower,upper] of fixtures) test(`exact band ${centre.length > 60 ? '1000 digits' : centre}`,()=>{
  const result=inspect(input(pricing(centre,min,max),[lower,upper]),sdk);
  assert.deepEqual(result.band,{lower,upper});
  assert.ok(result.counteroffers.every(o=>o.decision==='ACCEPTABLE'));
});
test('inclusive endpoints and unrounded sub-precision offers',()=>{
  const r=inspect(input(pricing(),['1.3999','1.4','1.40001','1.69999','1.7','1.70001']),sdk);
  assert.deepEqual(r.counteroffers.map(o=>o.decision),['REJECTED','ACCEPTABLE','ACCEPTABLE','ACCEPTABLE','ACCEPTABLE','REJECTED']);
});
for (const amount of ['01.5','1.50','1e0','+1',' 1.5','-1','0','0.0','.5','1.','NaN']) test(`refuse noncanonical/zero ${JSON.stringify(amount)}`,()=>{
  assert.throws(()=>inspect(input(pricing(amount)),sdk));
  assert.equal(inspect(input(pricing(),[amount]),sdk).counteroffers[0].reason,'INVALID_AMOUNT');
});
test('currency is bound exactly',()=>{
  for(const currency of ['USD','dem']) {
    const request=input(pricing(),['1.5']);request.counteroffers[0].currency=currency;
    assert.equal(inspect(request,sdk).counteroffers[0].reason,'CURRENCY_MISMATCH');
  }
});
test('unit and unknown fields cannot imply complete RFQ validation',()=>{
  const request=input(pricing(),['1.5']);request.counteroffers[0].unit='hour';
  assert.throws(()=>inspect(request,sdk));
});
test('invalid terms and resource limits',()=>{
  for(const p of [pricing('1',100),pricing('1',99.9),pricing('1.5',-1),pricing('1.5',10,Infinity),pricing('1.5','10'),pricing('1'.repeat(4097))]) assert.throws(()=>inspect(input(p),sdk));
  for (const v of [null,{},input(pricing(),Array(65).fill('1.5'))]) assert.throws(()=>inspect(v,sdk));
});
const cli=fileURLToPath(new URL('./cli.mjs',import.meta.url));
const dir=mkdtempSync(join(tmpdir(),'quote-band-test-'));
const run=(file,env=process.env)=>spawnSync(process.execPath,[cli,file],{env,encoding:'utf8',timeout:8000});
test('fresh CLI processes: positive, rejection, malformed, oversize, missing SDK, hash mismatch, recovery',()=>{
  try {
    const file=join(dir,'input.json');
    writeFileSync(file,JSON.stringify(input(pricing(),['1.4','1.7'])));
    let r=run(file);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).mode,'LOCAL_ONLY');
    writeFileSync(file,JSON.stringify(input(pricing(),['1.70001'])));
    r=run(file);assert.equal(r.status,1);assert.equal(JSON.parse(r.stdout).counteroffers[0].reason,'OUTSIDE_BAND');
    for(const bytes of ['{', ' '.repeat(65537)]) {writeFileSync(file,bytes);r=run(file);assert.equal(r.status,2);assert.equal(r.stdout,'');}
    writeFileSync(file,JSON.stringify(input(pricing())));
    r=run(file,{...process.env,DACS_SDK_ROOT:dir});assert.equal(r.status,2);assert.equal(JSON.parse(r.stderr).reason,'SDK_UNAVAILABLE');
    const fake=join(dir,'fake');
    mkdirSync(join(fake,'dist/negotiate'),{recursive:true});
    writeFileSync(join(fake,'dist/negotiate/fixedPrice.js'),'export const forged=true;');
    r=run(file,{...process.env,DACS_SDK_ROOT:fake});assert.equal(r.status,2);assert.equal(JSON.parse(r.stderr).reason,'SDK_HASH_MISMATCH');
    // Preserve the real entry bytes but force one dependency's asynchronous
    // import to hang. The CLI must stop and leave the next invocation usable.
    cpSync(join(process.env.DACS_SDK_ROOT,'dist'),join(fake,'dist'),{recursive:true});
    writeFileSync(join(fake,'package.json'),'{"type":"module"}');
    appendFileSync(join(fake,'dist/negotiate/jobId.js'),'\nawait new Promise(() => {});\n');
    r=run(file,{...process.env,DACS_SDK_ROOT:fake});assert.equal(r.status,2,r.stderr);assert.equal(JSON.parse(r.stderr).reason,'TIMEOUT');
    r=run(join(dir,'absent'));assert.equal(r.status,2);
    r=run(file);assert.equal(r.status,0,r.stderr); // failures left no persistent state/locks
  } finally {rmSync(dir,{recursive:true,force:true});}
});
