'use strict';
const download = document.getElementById('download');
if (download) download.addEventListener('click', () => {
  const text = `Access Gate — ${download.dataset.name}\nValid: ${download.dataset.start} to ${download.dataset.end} (Europe/Amsterdam)\nSingle use, ${download.dataset.duration} of access per code.\n\n${document.getElementById('codes').value}\n`;
  const url = URL.createObjectURL(new Blob([text], {type:'text/plain;charset=utf-8'}));
  const a = document.createElement('a'); a.href = url; a.download = `access-codes-${download.dataset.id}.txt`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
const batchForm = document.getElementById('batch-form');
if (batchForm) {
  const label = (value,unit) => `${value} ${Number(value) === 1 ? unit.slice(0,-1) : unit}`;
  const preview = () => { const f = new FormData(batchForm); document.getElementById('batch-summary').textContent = `${f.get('count')} single-use codes, valid for ${label(f.get('validity_value'),f.get('validity_unit'))} from generation. Each code grants ${label(f.get('access_value'),f.get('access_unit'))} from activation.`; };
  batchForm.addEventListener('input',preview); preview();
}
const extendForm = document.getElementById('extend-form');
if (extendForm) {
  const preview = () => {
    const f = new FormData(extendForm), value = Number(f.get('value'));
    const end = (Number(extendForm.dataset.expires) + value * (f.get('unit') === 'hours' ? 3600 : 60))*1000;
    const maximum = f.get('unit') === 'hours' ? 168 : 10080;
    document.getElementById('extension-preview').textContent = Number.isFinite(end) && Number.isInteger(value) && value > 0 && value <= maximum ? `New end time: ${new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Amsterdam',dateStyle:'medium',timeStyle:'medium'}).format(end)} (Europe/Amsterdam)` : 'Enter a positive whole duration of at most 7 days.';
  };
  extendForm.addEventListener('input',preview); preview();
}
const countdown = document.getElementById('access-countdown');
if (countdown) {
  let expiry = Number(countdown.dataset.expires), offset = 0, exclusionKind = null;
  const tick = () => {
    if (exclusionKind === 'ip' || exclusionKind === 'admin') { countdown.textContent = exclusionKind === 'ip' ? 'IP exclusion active. No access code required.' : 'Signed-in access active. Your login renews with use.'; return; }
    const left = Math.max(0,Math.ceil(expiry-Date.now()/1000-offset));
    countdown.textContent = left ? `Time remaining: ${Math.floor(left/3600)}h ${Math.floor(left%3600/60)}m ${left%60}s` : 'Access expired. Refresh this page to enter another unused code.';
  };
  const sync = async () => { try { const response = await fetch('/status',{cache:'no-store'}); if (!response.ok) return; const state = await response.json(); offset = state.server_time-Date.now()/1000; expiry = state.active ? state.expires : 0; exclusionKind = state.active ? state.kind : null; tick(); } catch (_) { /* Server-side checks remain authoritative. */ } };
  tick(); sync(); setInterval(tick,1000); setInterval(sync,5000);
}


// A committed portal document ends the form-action redirect chain.
const continueWebsite = document.getElementById('continue-website');
if (continueWebsite) window.location.replace(continueWebsite.href);

const formatTime = stamp => stamp ? new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Amsterdam',dateStyle:'short',timeStyle:'medium'}).format(new Date(stamp*1000)) : '—';
const remainingTime = seconds => { const n=Math.max(0,Math.ceil(seconds)); return `${Math.floor(n/3600)}h ${Math.floor(n%3600/60)}m ${n%60}s`; };
const cell = (row,text) => { const td=document.createElement('td'); td.textContent=text; row.append(td); return td; };
const link = (parent,label,href,classes='') => { const a=document.createElement('a'); a.textContent=label; a.href=href; a.className=classes; parent.append(a); return a; };
const sessionsPanel=document.getElementById('sessions-panel');
if (sessionsPanel) {
  let busy=false, offset=0;
  const tick=()=>document.querySelectorAll('[data-session-expires]').forEach(el=>{el.textContent=remainingTime(Number(el.dataset.sessionExpires)-Date.now()/1000-offset);});
  const refresh=async()=>{
    if(busy) return; busy=true;
    const status=document.getElementById('session-refresh');
    try {
      const query=new URLSearchParams({state:sessionsPanel.dataset.state,page:sessionsPanel.dataset.page});
      const response=await fetch('/admin/api/sessions?'+query,{cache:'no-store',redirect:'error',signal:AbortSignal.timeout(10000)});
      if(!response.ok) throw Error();
      const data=await response.json(); offset=data.server_time-Date.now()/1000;
      const rows=document.getElementById('session-rows'); rows.replaceChildren();
      for(const item of data.items){
        const row=document.createElement('tr');
        cell(row,item.session_id.slice(0,8)); cell(row,item.ip);
        link(cell(row,''),item.batch_name,'/admin/batches/'+encodeURIComponent(item.batch_id));
        cell(row,formatTime(item.started)); cell(row,formatTime(item.expires));
        const timer=cell(row,'—'); if(item.state==='active') timer.dataset.sessionExpires=item.expires;
        cell(row,item.state); const actions=cell(row,'');
        if(item.state==='active'){
          const path='/admin/access/'+encodeURIComponent(item.session_id);
          link(actions,'Extend',path+'/extend','button secondary'); actions.append(' ');
          link(actions,'Terminate',path+'/terminate','button danger');
        }
        rows.append(row);
      }
      if(!data.items.length){const row=document.createElement('tr');cell(row,'No matching browser sessions.').colSpan=8;rows.append(row);}
      document.getElementById('session-counts').textContent=`${data.total} matching sessions · ${data.counts.active||0} active · ${data.counts.expired||0} expired · ${data.counts.terminated||0} terminated · ${data.counts.revoked||0} revoked`;
      const pages=document.getElementById('session-pagination'); pages.replaceChildren();
      const pageLink=(label,page)=>link(pages,label,'?'+new URLSearchParams({state:sessionsPanel.dataset.state,page}));
      if(data.page>1)pageLink('Previous',data.page-1);
      const label=document.createElement('span');label.textContent=`Page ${data.page} of ${data.pages}`;pages.append(label);
      if(data.page<data.pages)pageLink('Next',data.page+1);
      status.textContent='Last checked '+formatTime(data.server_time)+'. Refreshes every 5 seconds.';tick();
    } catch(_){ status.textContent='Session status is stale. Refresh or sign in again; server-side access checks remain active.'; }
    finally { busy=false; }
  };
  refresh();setInterval(refresh,5000);setInterval(tick,1000);
}
const systemHealth=document.getElementById('system-health');
if(systemHealth){
  let busy=false;
  const refresh=async()=>{
    if(busy)return;busy=true;
    const status=document.getElementById('health-time');
    try{
      const response=await fetch('/admin/api/health',{cache:'no-store',redirect:'error',signal:AbortSignal.timeout(10000)});
      if(!response.ok)throw Error();const data=await response.json();
      document.getElementById('health-version').textContent=data.version;
      document.getElementById('health-state').textContent=data.stale?'Unknown (stale)':data.state;
      status.textContent=(data.stale?'Stale / checks running. ':'')+'Last checked '+formatTime(data.checked_at)+'. Refreshes every 15 seconds.';
      const rows=document.getElementById('health-rows');rows.replaceChildren();
      for(const check of data.checks){const row=document.createElement('tr');cell(row,check.name);cell(row,check.state);cell(row,check.detail+' '+check.action).className='health-detail';rows.append(row);}
    }catch(_){status.textContent='System status is stale. Refresh or sign in again.';document.getElementById('health-state').textContent='Unknown';}
    finally{busy=false;}
  };
  refresh();setInterval(refresh,15000);
}

const requestNotifications=document.getElementById('request-notifications');
if(requestNotifications){
  let busy=false;
  const refresh=async()=>{
    if(busy)return;busy=true;
    try{
      const response=await fetch('/admin/api/notifications',{cache:'no-store',redirect:'error',signal:AbortSignal.timeout(10000)});
      if(!response.ok)throw Error();const data=await response.json();
      requestNotifications.textContent=`(${data.unread})`;requestNotifications.title='Unread access requests';
    }catch(_){requestNotifications.title='Notification count is stale. Refresh or sign in again.';}
    finally{busy=false;}
  };
  refresh();setInterval(refresh,10000);
}

const requestDecision=document.getElementById('request-decision');
if(requestDecision){
  let busy=false,finished=false;
  const refresh=async()=>{
    if(busy||finished)return;busy=true;
    const status=document.getElementById('request-decision-status'),next=document.getElementById('request-continue');
    try{
      const response=await fetch('/request-access/status?'+new URLSearchParams({request:requestDecision.dataset.requestId}),{cache:'no-store',redirect:'error',signal:AbortSignal.timeout(10000)});
      if(!response.ok)throw Error();const item=await response.json();
      if(item.active&&item.continue_url){
        const target=new URL(item.continue_url,window.location.href);
        if(target.origin!==window.location.origin||!target.pathname.startsWith('/request-access/'))throw Error();
        next.href=target.href;next.hidden=false;status.textContent='Approved until '+formatTime(item.expires)+'. Opening your website…';
        finished=true;window.location.replace(target.href);
      }else{
        next.hidden=true;
        status.textContent=item.state==='pending'?'Waiting for administrator approval…':item.state==='approved'?'Approved, but this session has ended. Send a new request if needed.':item.state==='denied'?'Your request was denied.':item.state==='expired'?'This request expired. Send a new request if needed.':'This request is closed.';
        finished=item.state!=='pending';
      }
    }catch(_){status.textContent='Could not refresh the decision. Retry or reload this page.';}
    finally{busy=false;}
  };
  refresh();setInterval(refresh,3000);
}
