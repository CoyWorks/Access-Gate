"""Best-effort bounded delivery of code-scoped visit metadata."""
import asyncio
import contextlib
import json
import secrets
import time
import aiohttp
from .operations import page_path


class GatewayActivity:
    def start_activity(self):
        self.activity_queue=asyncio.Queue(maxsize=1000)
        self.activity_dropped=0;self.activity_last_success=None
        self.activity_worker=asyncio.create_task(self.deliver_activity())

    async def stop_activity(self):
        if not getattr(self,'activity_worker',None):return
        try:await asyncio.wait_for(self.activity_queue.join(),2)
        except asyncio.TimeoutError:self.activity_dropped+=self.activity_queue.qsize()
        self.activity_worker.cancel()
        with contextlib.suppress(asyncio.CancelledError):await self.activity_worker

    def queue_visit(self,request,host,auth,status):
        sid=auth.get('X-Gate-Code-Session','')
        if not sid or auth.get('X-Gate-Visit-Mode')=='off':return
        destination=request.headers.get('Sec-Fetch-Dest','')
        navigation=request.method=='GET' and (destination in ('document','iframe') or (not destination and 'text/html' in request.headers.get('Accept','')))
        record=dict(id=secrets.token_hex(16),session_id=sid,origin='https://'+host,status=status,navigation=navigation,created=time.time())
        # Never place raw query strings/tickets in the queue or logs.
        record['path']=page_path(request.raw_path) if navigation and auth.get('X-Gate-Visit-Mode')=='pages' else None
        try:self.activity_queue.put_nowait(record)
        except asyncio.QueueFull:self.activity_dropped+=1

    async def activity_post(self,path,data):
        async with self.local.post(self.api_url+path,json=data,headers={'X-Gate-Key':self.key},allow_redirects=False) as response:
            body=await response.content.read(1025)
            if len(body)>1024 or response.status!=200:raise OSError('Activity delivery failed.')

    async def deliver_activity(self):
        last_cleanup=0
        while True:
            try:record=await asyncio.wait_for(self.activity_queue.get(),timeout=60)
            except asyncio.TimeoutError:record=None
            if record is not None:
                try:
                    for attempt in range(2):
                        try:
                            await self.activity_post('/internal/activity/visit',record)
                            self.activity_last_success=time.time();break
                        except (aiohttp.ClientError,asyncio.TimeoutError,OSError):
                            if attempt:self.activity_dropped+=1
                finally:self.activity_queue.task_done()
            if time.monotonic()-last_cleanup>=60:
                try:await self.activity_post('/internal/activity/cleanup',{})
                except (aiohttp.ClientError,asyncio.TimeoutError,OSError):pass
                last_cleanup=time.monotonic()
