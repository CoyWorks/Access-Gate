'use strict';
const assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
  const elements={},calls=[];let enabled=false,unsubscribed=false;
  for(const id of ['admin-app','push-status','push-enable','push-disable','push-test','app-install'])elements[id]={dataset:{csrf:'csrf-test'},hidden:true,addEventListener(event,fn){this[event]=fn;}};
  const publicKey=Buffer.alloc(65,1).toString('base64url');
  const subscription={endpoint:'https://fcm.googleapis.com/fcm/send/test',unsubscribe:async()=>{unsubscribed=true;}};
  const registration={active:{},pushManager:{getSubscription:async()=>subscription,subscribe:async()=>{throw Error('Existing subscription should be reused.');}}};
  const notifications={requestPermission:async()=>{calls.push('permission');return 'granted';}};
  const context={document:{getElementById:id=>elements[id]},window:{isSecureContext:true,PushManager:function(){},Notification:notifications,addEventListener(){}},Notification:notifications,navigator:{serviceWorker:{register:async(url,opts)=>{calls.push(['register',url,opts.scope]);return registration;}}},URLSearchParams,AbortSignal,Uint8Array,atob:s=>Buffer.from(s,'base64').toString('binary'),fetch:async(url,opts={})=>{
    if(opts.method==='POST'){const action=opts.body.get('action');assert.equal(opts.body.get('csrf'),'csrf-test');calls.push(action);if(action==='enable')enabled=true;if(action==='disable')enabled=false;}
    return {ok:true,json:async()=>({public_key:publicKey,devices:enabled?[{id:'device'}]:[]})};
  }};
  vm.runInNewContext(fs.readFileSync('static/admin-app.js','utf8'),context);await flush();
  assert.equal(calls.includes('permission'),false);assert.equal(calls.includes('enable'),false);
  await elements['push-enable'].click();assert.equal(calls.includes('permission'),true);assert.equal(enabled,true);
  await elements['push-test'].click();assert.equal(calls.includes('test'),true);
  await elements['push-disable'].click();assert.equal(enabled,false);assert.equal(unsubscribed,true);
  const handlers={},shown=[],opened=[];let stored=false;
  const self={location:{origin:'https://portal.example'},addEventListener:(name,fn)=>handlers[name]=fn,skipWaiting:async()=>{},registration:{showNotification:async(title,opts)=>shown.push({title,...opts})},clients:{claim:async()=>{},matchAll:async()=>[],openWindow:async target=>opened.push(target)}};
  vm.runInNewContext(fs.readFileSync('static/admin-sw.js','utf8'),{self,URL,fetch:async()=>{throw Error('offline');},Response});
  let waiting;handlers.push({data:null,waitUntil:p=>waiting=p});await waiting;
  assert.equal(shown.length,1);assert.match(shown[0].body,/New access request/);assert.equal(shown[0].tag,'access-gate-requests');
  handlers.notificationclick({notification:{close(){}},waitUntil:p=>waiting=p});await waiting;assert.deepEqual(opened,['https://portal.example/admin/requests?state=pending']);
  let reply;handlers.fetch({request:{url:'https://portal.example/admin',method:'GET',mode:'navigate'},respondWith:p=>reply=p});const offline=await reply;assert.equal(offline.status,503);assert.match(await offline.text(),/VPN/);
  reply=null;handlers.fetch({request:{url:'https://portal.example/admin/batch',method:'POST',mode:'navigate'},respondWith:p=>reply=p});assert.equal(reply,null);
  console.log('Admin app opt-in, subscription controls, generic background push, safe click target and offline behavior passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
