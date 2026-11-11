'use strict';
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
// Never cache admin HTML, credentials, codes, API responses or submitted forms.
self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url);
  if(event.request.method==='GET' && event.request.mode==='navigate' && url.origin===self.location.origin && url.pathname.startsWith('/admin')){
    event.respondWith(fetch(event.request).catch(()=>new Response('<!doctype html><meta name="viewport" content="width=device-width"><title>Access Gate offline</title><h1>Access Gate is offline</h1><p>Connect to your VPN or local network, then try again.</p><a href="/admin">Open administration</a>',{status:503,headers:{'Content-Type':'text/html;charset=utf-8','Cache-Control':'no-store'}})));
  }
});
self.addEventListener('push',event=>{
  // Fixed text, including for test pushes. No request details leave the portal.
  event.waitUntil(self.registration.showNotification('Access Gate',{
    body:'New access request. Open administration to review pending requests.',
    icon:'/admin/icon-192.png',badge:'/admin/icon-192.png',tag:'access-gate-requests',renotify:true
  }));
});
self.addEventListener('notificationclick',event=>{
  event.notification.close();
  const target=new URL('/admin/requests?state=pending',self.location.origin).href;
  event.waitUntil((async()=>{
    const windows=await self.clients.matchAll({type:'window',includeUncontrolled:true});
    for(const client of windows){
      const url=new URL(client.url);
      if(url.origin===self.location.origin && url.pathname.startsWith('/admin')){
        try{await client.navigate(target);await client.focus();return;}catch(_){/* Open a fresh admin window. */}
      }
    }
    await self.clients.openWindow(target);
  })());
});
