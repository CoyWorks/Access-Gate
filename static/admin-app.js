'use strict';
const appPanel=document.getElementById('admin-app');
if(appPanel){
  const status=document.getElementById('push-status'),enable=document.getElementById('push-enable'),disable=document.getElementById('push-disable'),test=document.getElementById('push-test'),install=document.getElementById('app-install');
  let registration=null,installPrompt=null,server=null;
  const csrf=appPanel.dataset.csrf;
  const post=async(action,endpoint='')=>{
    const body=new URLSearchParams({csrf,action,endpoint});
    const response=await fetch('/admin/api/push',{method:'POST',body,credentials:'same-origin',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000)});
    if(!response.ok){let message='Notification setup failed. Reload or sign in again.';try{message=(await response.json()).error||message;}catch(_){}throw Error(message);}
    return response.json();
  };
  const refresh=async()=>{
    const response=await fetch('/admin/api/push',{cache:'no-store',credentials:'same-origin',redirect:'error'});
    if(!response.ok)throw Error('Sign in again to manage notifications.');server=await response.json();
    test.disabled=!server.devices.length;
    status.textContent=server.devices.length?'Notifications enabled for this browser login. Use Send test to verify delivery.':'Notifications are disabled for this browser login.';
    for(const device of server.devices)if(device.last_error)status.textContent+=' '+device.last_error;
  };
  const keyBytes=value=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-value.length%4)%4)),c=>c.charCodeAt(0));
  window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();installPrompt=event;install.hidden=false;});
  install.addEventListener('click',async()=>{if(!installPrompt)return;await installPrompt.prompt();await installPrompt.userChoice;installPrompt=null;install.hidden=true;});
  const supported=window.isSecureContext && 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  if(!supported){status.textContent='Push is unavailable here. Use trusted HTTPS. On iPhone/iPad, add the app to the Home Screen and open it there first.';enable.disabled=true;test.disabled=true;}
  else{
    // Register now, but never ask for permission or subscribe without a button click.
    const ready=navigator.serviceWorker.register('/admin/sw.js',{scope:'/admin',updateViaCache:'none'}).then(async value=>{
      registration=value;
      if(!registration.active)await new Promise((resolve,reject)=>{const worker=registration.installing||registration.waiting;if(!worker)return reject(Error('Service worker did not start.'));if(worker.state==='activated')return resolve();worker.addEventListener('statechange',()=>{if(worker.state==='activated')resolve();else if(worker.state==='redundant')reject(Error('Service worker failed.'));});});
      await refresh();
    }).catch(error=>{status.textContent='Cannot start the admin app: '+error.message+' Check VPN connectivity and certificate trust.';throw error;});
    ready.catch(()=>{});
    enable.addEventListener('click',async()=>{
      enable.disabled=true;
      try{
        // Permission must be requested directly from this user gesture (not after network awaits).
        const permission=await Notification.requestPermission();
        if(permission!=='granted')throw Error('Notifications were not allowed. Review this site in your browser/phone notification settings.');
        await ready;await refresh();
        let subscription=await registration.pushManager.getSubscription();
        if(!subscription)subscription=await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:keyBytes(server.public_key)});
        await post('enable',subscription.endpoint);await refresh();
      }catch(error){status.textContent=error.message;}finally{enable.disabled=false;}
    });
    disable.addEventListener('click',async()=>{
      try{await ready;await post('disable');const sub=await registration.pushManager.getSubscription();if(sub)await sub.unsubscribe();await refresh();}catch(error){status.textContent=error.message;}
    });
    test.addEventListener('click',async()=>{
      try{await post('test');status.textContent='Test queued. It uses the same generic new-request alert. Delivery depends on the browser push service; refresh to see provider errors.';}catch(error){status.textContent=error.message;}
    });
  }
}
