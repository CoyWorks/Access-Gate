import asyncio
from types import SimpleNamespace
import unittest
from access_gate.gateway_activity import GatewayActivity


class GatewayActivityTests(unittest.IsolatedAsyncioTestCase):
    async def test_retry_uses_same_id_and_reports_delivery_failure(self):
        activity=GatewayActivity();calls=[]
        async def post(path,record):
            if path.endswith('/visit'):
                calls.append(record['id'])
                if len(calls)==1:raise OSError('First delivery timed out.')
        activity.activity_post=post;activity.start_activity()
        activity.activity_queue.put_nowait(dict(id='a'*32))
        await asyncio.wait_for(activity.activity_queue.join(),1)
        self.assertEqual(calls,['a'*32,'a'*32]);self.assertEqual(activity.activity_dropped,0)
        self.assertIsNotNone(activity.activity_last_success)
        async def fail(path,record):raise OSError('Unavailable')
        activity.activity_post=fail;activity.activity_queue.put_nowait(dict(id='b'*32))
        await asyncio.wait_for(activity.activity_queue.join(),1)
        self.assertEqual(activity.activity_dropped,1)
        await activity.stop_activity()
    async def test_queue_is_bounded_and_path_collection_requires_explicit_page_mode(self):
        activity=GatewayActivity();activity.activity_queue=asyncio.Queue(maxsize=1);activity.activity_dropped=0
        request=SimpleNamespace(method='GET',headers={'Sec-Fetch-Dest':'document'},raw_path='/article?secret=NOT-QUEUED#fragment')
        auth={'X-Gate-Code-Session':'a'*32,'X-Gate-Visit-Mode':'domains'}
        activity.queue_visit(request,'example.org',auth,200)
        record=activity.activity_queue.get_nowait();activity.activity_queue.task_done()
        self.assertIsNone(record['path']);self.assertNotIn('NOT-QUEUED',str(record))
        auth['X-Gate-Visit-Mode']='pages';activity.queue_visit(request,'example.org',auth,200)
        activity.queue_visit(request,'example.org',auth,200);self.assertEqual(activity.activity_dropped,1)
        record=activity.activity_queue.get_nowait();self.assertEqual(record['path'],'/article');activity.activity_queue.task_done()
        auth['X-Gate-Visit-Mode']='off';activity.queue_visit(request,'example.org',auth,200);self.assertTrue(activity.activity_queue.empty())
        activity.queue_visit(request,'example.org',{},200);self.assertTrue(activity.activity_queue.empty())
