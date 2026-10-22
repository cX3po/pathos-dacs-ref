import{test}from'node:test';import assert from'node:assert/strict';
import{mkdtemp,writeFile,symlink,mkdir}from'node:fs/promises';import{tmpdir}from'node:os';import{join}from'node:path';
import{loadSdk,evaluate,validateSpec,boundedFile,liveDemo,endpoint,DEFAULT_SUBJECT,demoExitCode,runIsolated}from'./main.mjs';
const sdk=await loadSdk();
test('real SDK JSONPath filter preserves audit object',()=>{const r=evaluate(sdk,{format:'json',successJsonPath:'$.items[?@.ok == true]',dataMap:{chosen:'$.items[?@.ok == true]'}},'{"items":[{"ok":false},{"ok":true,"n":7}]}');assert.equal(r.decision,'pass');assert.deepEqual(r.data.chosen,{ok:true,n:7});});
test('missing and malformed differ',()=>{assert.equal(evaluate(sdk,{format:'json',successJsonPath:'$.x'},'{}').decision,'fail');assert.equal(evaluate(sdk,{format:'json',successJsonPath:'$.x'},'{').decision,'error');});
test('negative absence requires completeness; match remains fail',()=>{const s={format:'json',successJsonPath:'$.blocked[*]'};assert.equal(evaluate(sdk,s,'{"blocked":[]}',{negativeMatch:true}).decision,'indeterminate');assert.equal(evaluate(sdk,s,'{"blocked":[]}',{negativeMatch:true,listComplete:true}).decision,'pass');assert.equal(evaluate(sdk,s,'{"blocked":[1]}',{negativeMatch:true,listComplete:true}).decision,'fail');});
test('indeterminate marker outranks apparent success',()=>assert.equal(evaluate(sdk,{format:'json',successJsonPath:'$.x',indeterminateOn:[{jsonPath:'$.unavailable'}]},'{"x":1,"unavailable":true}').decision,'indeterminate'));
test('actual CSS XPath RE2 engines',()=>{assert.equal(evaluate(sdk,{format:'html',successSelector:'.ok',dataMap:{text:'.ok'}},'<script>throw 1</script><b class="ok">yes</b>').data.text,'yes');assert.equal(evaluate(sdk,{format:'xml',successXPath:'/root/ok'},'<root><ok>yes</ok></root>').decision,'pass');assert.equal(evaluate(sdk,{format:'raw',matcher:'hello ([a-z]+)'},'hello demos').decision,'pass');assert.equal(evaluate(sdk,{format:'raw',matcher:'(a)\\1'},'aa').decision,'error');});
test('spec size and context guards',()=>{for(const s of[{format:'json'},{format:'evil',matcher:'x'},{format:'raw',matcher:'x',dataMap:{}},{format:'json',successJsonPath:'$.x',indeterminateOn:[{selector:'x'}]}])assert.throws(()=>validateSpec(s));assert.throws(()=>evaluate(sdk,{format:'json',successJsonPath:'$'},'x'.repeat(262145)));assert.throws(()=>evaluate(sdk,{format:'json',successJsonPath:'$'},'{}',{negativeMatch:'false'}));});
test('file input rejects symlink directory oversize invalid UTF8',async()=>{const p=await mkdtemp(join(tmpdir(),'recipe-test-'));await writeFile(join(p,'body'),'{}');await symlink(join(p,'body'),join(p,'link'));await mkdir(join(p,'dir'));assert.equal(await boundedFile(join(p,'body'),16),'{}');for(const f of['link','dir'])await assert.rejects(()=>boundedFile(join(p,f),16));await assert.rejects(()=>boundedFile(join(p,'body'),1));await writeFile(join(p,'bad'),Buffer.from([255]));await assert.rejects(()=>boundedFile(join(p,'bad'),16));});
test('endpoint and DID guard precedes identity read',async()=>{let calls=0;const readIdentity=async()=>{calls++;return{primaryClaim:DEFAULT_SUBJECT,claims:[]};};for(const rpc of['https://evil.test','https://node2.demos.sh@evil.test','http://node2.demos.sh','https://node2.demos.sh/path','https://node2.demos.sh:444'])await assert.rejects(()=>liveDemo(sdk,{rpc,readIdentity}));await assert.rejects(()=>liveDemo(sdk,{did:'0x123',readIdentity}));assert.equal(calls,0);assert.equal(endpoint('https://node2.demos.sh/'),'https://node2.demos.sh');});
test('testnet projection yields three states without raw metadata',async()=>{const r=await liveDemo(sdk,{readIdentity:async()=>({primaryClaim:DEFAULT_SUBJECT,claims:[],raw:{secret:'do-not-emit'}})});assert.deepEqual(r.cases.slice(0,3).map(x=>x.decision),['pass','fail','indeterminate']);assert.ok(!JSON.stringify(r).includes('do-not-emit'));await assert.rejects(()=>liveDemo(sdk,{readIdentity:async()=>({primaryClaim:'other',claims:[]})}));});

test('demo parser errors and unknown verdicts never exit success',()=>{
 assert.equal(demoExitCode({cases:[{decision:'pass'},{decision:'fail'},{decision:'indeterminate'}]}),0);
 for(const cases of [[{decision:'error'}],[{decision:'unknown'}],[]])assert.equal(demoExitCode({cases}),2);
});
test('independent parent kills a costly size-compliant JSONPath worker',async()=>{
 const p=await mkdtemp(join(tmpdir(),'recipe-cost-'));
 let body='0';for(let i=0;i<35;i++)body='['+body+']';
 await writeFile(join(p,'body'),body);await writeFile(join(p,'spec'),JSON.stringify({format:'json',successJsonPath:'$'+'[0,0]'.repeat(35)}));
 const start=Date.now();const r=await runIsolated(['evaluate','--spec',join(p,'spec'),'--body',join(p,'body')],{timeoutMs:1000});
 assert.equal(r.timedOut,true);assert.equal(r.code,2);assert.equal(r.stdout,'');assert.ok(Date.now()-start<4000);
});
