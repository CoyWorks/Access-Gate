import io
import re
import time
import unittest
from unittest.mock import patch
from access_gate.core import GateError
from access_gate.exports import options,qr_url,qr_svg,pdf_cards
from test_browser_portal import BrowserWebFixture


class ExportTests(BrowserWebFixture,unittest.TestCase):
    def setUp(self):
        super().setUp();self.request('/admin/login','POST',dict(csrf=self.csrf(),password='admin'))
    def generate(self,**kwargs):
        values=dict(csrf=self.csrf(),name='<Test & café>',count='7',validity_value='2',validity_unit='days',access_value='1',access_unit='hours',export='text')
        values.update(kwargs);return self.request('/admin/batch','POST',values)
    def test_print_cards_escape_names_and_show_correct_validity_duration(self):
        response=self.generate(export='print',qr='1');self.assertEqual(response.status_code,200)
        html=response.data.decode();self.assertEqual(html.count('class="code-card"'),7)
        self.assertIn('&lt;Test &amp; café&gt;',html);self.assertIn('1 hour of access',html)
        self.assertEqual(html.count('<svg '),7);self.assertNotIn('<script>',html)
        self.assertIn('Europe/Amsterdam',html)
        codes=re.findall(r'class="card-code">([^<]+)',html)
        with self.store.connect() as db:
            for code in codes:self.assertIsNotNone(db.execute('SELECT id FROM codes WHERE digest=?',(self.store.digest(code),)).fetchone())
        with self.store.connect() as db:
            dump=' '.join(db.iterdump())
            for code in codes:self.assertNotIn(code,dump)
    def test_pdf_is_downloadable_has_multiple_pages_and_no_cache(self):
        response=self.generate(export='pdf',qr='1');self.assertEqual(response.status_code,200)
        self.assertEqual(response.mimetype,'application/pdf');self.assertTrue(response.data.startswith(b'%PDF-'))
        self.assertIn('attachment;',response.headers['Content-Disposition']);self.assertEqual(response.headers['Cache-Control'],'no-store')
        from pypdf import PdfReader
        pdf=PdfReader(io.BytesIO(response.data));self.assertEqual(len(pdf.pages),2)
        text=''.join(page.extract_text() for page in pdf.pages)
        self.assertIn('<Test & café>',text);self.assertIn('1 hour',text);self.assertIn('Single use',text)
        self.assertEqual(len(re.findall(r'[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}',text)),7)
    def test_invalid_output_and_qr_limits_do_not_create_batches(self):
        for kwargs in (dict(export='bad'),dict(export='text',qr='1'),dict(export='pdf',qr='1',count='201')):
            self.assertEqual(self.generate(**kwargs).status_code,400)
        self.assertEqual(self.store.list_batches()['total'],0)
    def test_export_failure_preserves_the_existing_batch_codes(self):
        with patch('access_gate.exports.pdf_cards',side_effect=RuntimeError('test')):response=self.generate(export='pdf')
        self.assertIn(b'Export failed',response.data);self.assertEqual(self.store.list_batches()['total'],1)
        codes=re.findall(r'[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}',response.data.decode())
        self.assertEqual(len(codes),7)
        self.store.redeem(codes[0],'10.40.22.30',browser_token='a'*64)
        self.assertTrue(self.store.browser_grant('a'*64))
    def test_qr_uses_fragment_and_never_silently_consumes_code(self):
        _,codes=self.store.create_batch(count=1);url=qr_url('https://10.40.22.5',codes[0])
        self.assertEqual(url,'https://10.40.22.5/#code='+codes[0]);self.assertNotIn('?',url)
        self.request('/#code='+codes[0]);self.assertIsNone(self.store.browser_grant('a'*64))
        self.assertIn('<svg',qr_svg(url))
    def test_large_batch_has_all_cards_and_no_plaintext_retrieval(self):
        response=self.generate(export='print',count='1000');self.assertEqual(response.status_code,200)
        self.assertEqual(response.data.count(b'class="code-card"'),1000)
        self.assertEqual(self.store.list_batches()['total'],1)
        self.assertEqual(self.request('/admin/batches/'+self.store.list_batches()['items'][0]['id']).data.count(b'class="card-code"'),0)
    def test_export_requires_admin_and_csrf(self):
        other=self.app.test_client();self.assertEqual(self.request('/admin/batch','POST',dict(csrf=self.csrf(other)),client=other).status_code,302)
        self.assertEqual(self.request('/admin/batch','POST',{}).status_code,400)
