// Run with node tests/test_admin_ui.js; no DOM/test dependencies required.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Element {
  constructor(tag='div'){this.tag=tag;this.children=[];this.dataset={};this.textContent='';this.className='';}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=items;}
}
async function scenario(ids,answer,fragment){
  const elements=Object.fromEntries(ids.map(id=>[id,new Element()])),intervals=[],navigations=[];
  if(elements['request-decision'])elements['request-decision'].dataset.requestId='a'.repeat(32);
  if(elements['sessions-panel'])Object.assign(elements['sessions-panel'].dataset,{state:'active',page:'1'});
  const document={getElementById:id=>elements[id]||null,createElement:tag=>new Element(tag),querySelectorAll:()=>[]};
  let fail=false;
  const cleared=[];
  const context={document,Intl,Date,URL,URLSearchParams,AbortSignal,fetch:async()=>{if(fail)throw Error();return {ok:true,json:async()=>answer};},setInterval:fn=>intervals.push(fn),window:{history:{replaceState:(_state,_title,url)=>cleared.push(url)},location:{hash:fragment||'',pathname:'/',search:'',href:'https://portal.example/request-access',origin:'https://portal.example',replace:url=>navigations.push(url)}}};
  vm.runInNewContext(fs.readFileSync('static/gate.js','utf8'),context);
  await new Promise(resolve=>setImmediate(resolve));
  return {elements,intervals,navigations,cleared,fail:()=>{fail=true;}};
}
(async()=>{
 const qr=await scenario(['code'],{},'#code=ABCD-2345');
 assert.equal(qr.elements.code.value,'ABCD-2345');assert.deepEqual(qr.cleared,['/']);assert.equal(qr.navigations.length,0);
 const invalidQR=await scenario(['code'],{},'#code=<script>');assert.equal(invalidQR.elements.code.value,undefined);
 const approved=await scenario(['request-decision','request-decision-status','request-continue'],{state:'approved',active:true,expires:Date.now()/1000+900,continue_url:'/request-access/'+'a'.repeat(32)+'/continue'});
 assert.equal(approved.navigations[0],'https://portal.example/request-access/'+'a'.repeat(32)+'/continue');
 assert.equal(approved.elements['request-continue'].hidden,false);
 const denied=await scenario(['request-decision','request-decision-status','request-continue'],{state:'denied',active:false});
 assert.match(denied.elements['request-decision-status'].textContent,/denied/);assert.equal(denied.navigations.length,0);
 const foreign=await scenario(['request-decision','request-decision-status','request-continue'],{state:'approved',active:true,continue_url:'https://evil.example/'});
 assert.equal(foreign.navigations.length,0);assert.match(foreign.elements['request-decision-status'].textContent,/Could not refresh/);
 const excluded=await scenario(['access-countdown'],{active:true,kind:'ip',expires:null,server_time:Date.now()/1000});
 assert.match(excluded.elements['access-countdown'].textContent,/IP exclusion active/);
 const notifications=await scenario(['request-notifications'],{unread:3});
 assert.equal(notifications.elements['request-notifications'].textContent,'(3)');
 notifications.fail();await notifications.intervals[0]();assert.match(notifications.elements['request-notifications'].title,/stale/);
 const sessions=await scenario(['sessions-panel','session-refresh','session-counts','session-rows','session-pagination'],{
  server_time:1000,total:1,counts:{active:1},page:1,pages:1,
  items:[{session_id:'a'.repeat(32),ip:'10.40.22.99',batch_id:'b'.repeat(16),batch_name:'<script>unsafe()</script>',started:900,expires:1900,state:'active'}]
 });
 const row=sessions.elements['session-rows'].children[0];
 assert.equal(row.children[2].children[0].textContent,'<script>unsafe()</script>');
 assert.equal(row.children[2].children[0].tag,'a');
 assert.equal(row.children[7].children[0].href,'/admin/access/'+'a'.repeat(32)+'/extend');
 assert.equal(row.children[7].children[2].href,'/admin/access/'+'a'.repeat(32)+'/terminate');
 sessions.fail();await sessions.intervals[0]();assert.match(sessions.elements['session-refresh'].textContent,/stale/);
 const health=await scenario(['system-health','health-time','health-version','health-state','health-rows'],{
  version:'0.6.0',state:'warning',checked_at:1000,stale:true,checks:[{name:'Clock',state:'unknown',detail:'Cannot verify.',action:'Check server.'}]
 });
 assert.equal(health.elements['health-state'].textContent,'Unknown (stale)');
 assert.match(health.elements['health-time'].textContent,/Stale/);
 assert.equal(health.elements['health-rows'].children[0].children[2].textContent,'Cannot verify. Check server.');
 health.fail();await health.intervals[0]();assert.equal(health.elements['health-state'].textContent,'Unknown');
 console.log('Admin UI polling, safe text rendering, action links and stale/error states passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
