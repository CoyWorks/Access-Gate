"""One-time batch exports. Full codes are never recovered from stored hashes."""
import datetime as dt
import io
from pathlib import Path
from urllib.parse import urlsplit
from markupsafe import Markup
from .core import GateError,TZ,positive_int


def options(kind,qr,count):
    if kind not in ('text','print','pdf'):raise GateError('Choose text, printable cards or PDF.')
    count=positive_int(count,'Number of codes',1000)
    if qr and kind=='text':raise GateError('Choose printable cards or PDF for QR codes.')
    if qr and count>200:raise GateError('QR exports support at most 200 codes per batch. Larger batches can be printed without QR codes.')
    if kind=='pdf' or qr:
        try:import reportlab
        except ImportError:raise GateError('Export support is not installed. Run the normal updater first.') from None
    return kind,qr


def qr_url(portal,code):
    # Fragment values are not sent in HTTP requests or ordinary server access logs.
    parsed=urlsplit(portal)
    if parsed.scheme!='https' or parsed.query or parsed.fragment or parsed.path not in ('','/'):raise GateError('QR codes require the canonical HTTPS portal origin.')
    return portal.rstrip('/')+'/#code='+code


def matrix(url):
    from reportlab.graphics.barcode.qrencoder import QRCode,QRErrorCorrectLevel
    qr=QRCode(None,QRErrorCorrectLevel.M);qr.addData(url);qr.make()
    return qr.modules


def qr_svg(url):
    modules=matrix(url);size=len(modules)+8
    cells=''.join(f'M{x+4},{y+4}h1v1h-1z' for y,row in enumerate(modules) for x,dark in enumerate(row) if dark)
    return Markup(f'<svg class="code-qr" role="img" aria-label="Scan to prefill this code" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg"><rect width="{size}" height="{size}" fill="white"/><path d="{cells}" fill="black"/></svg>')


def local(stamp):return dt.datetime.fromtimestamp(stamp,TZ).strftime('%d-%m-%Y %H:%M')


def label(seconds):
    return f'{seconds//3600} hour'+('' if seconds==3600 else 's') if seconds%3600==0 else f'{seconds//60} minutes'


def pdf_cards(codes,batch,portal,qr=False):
    from reportlab.pdfgen.canvas import Canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    font='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
    if not Path(font).is_file():raise GateError('PDF fonts are not installed. Run the normal updater first.')
    if 'AccessGate' not in pdfmetrics.getRegisteredFontNames():pdfmetrics.registerFont(TTFont('AccessGate',font))
    output=io.BytesIO();canvas=Canvas(output,pagesize=A4,pageCompression=1)
    canvas.setTitle('Access Gate code cards');canvas.setAuthor('Access Gate')
    width,height=A4;margin=28;gap=12;card_w=(width-2*margin-gap)/2;card_h=(height-2*margin-2*gap)/3
    def text(x,y,value,size=9):canvas.setFont('AccessGate',size);canvas.drawString(x,y,value)
    def lines(value,max_width,size=9):
        result=[];line=''
        for character in value:
            if pdfmetrics.stringWidth(line+character,'AccessGate',size)>max_width:
                result.append(line);line=''
            line+=character
        result.append(line);return result
    for i,code in enumerate(codes):
        if i and i%6==0:canvas.showPage()
        column=i%2;row=(i%6)//2;x=margin+column*(card_w+gap);y=height-margin-(row+1)*card_h-row*gap
        canvas.setStrokeColorRGB(.65,.65,.65);canvas.roundRect(x,y,card_w,card_h,6)
        text(x+12,y+card_h-23,'ACCESS GATE',10)
        top=y+card_h-41
        for line in lines(batch['name'],card_w-24)[:3]:text(x+12,top,line);top-=12
        text(x+12,y+card_h-98,code,20)
        text(x+12,y+card_h-116,'Single use · '+label(batch['access_seconds']),9)
        text(x+12,y+card_h-133,'Activate between (Europe/Amsterdam):',8)
        text(x+12,y+card_h-146,local(batch['starts'])+' – '+local(batch['ends']),8)
        if qr:
            modules=matrix(qr_url(portal,code));square=72;step=square/(len(modules)+8)
            canvas.setFillColorRGB(1,1,1);canvas.rect(x+12,y+29,square,square,fill=1,stroke=0);canvas.setFillColorRGB(0,0,0)
            path=canvas.beginPath()
            for yy,qrrow in enumerate(modules):
                for xx,dark in enumerate(qrrow):
                    if dark:path.rect(x+12+(xx+4)*step,y+29+(len(modules)+3-yy)*step,step,step)
            canvas.drawPath(path,fill=1,stroke=0)
            text(x+92,y+67,'Scan to prefill.',8);text(x+92,y+54,'Then press Activate.',8)
        for j,line in enumerate(lines(portal,card_w-24,8)[:2]):text(x+12,y+18-j*10,line,8)
    canvas.save();return output.getvalue()
