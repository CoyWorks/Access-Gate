#!/usr/bin/python3
"""Reject hidden or unidentifiable TLS names before Squid's splice decision."""
import base64
import sys
import urllib.parse


def visible_sni(encoded):
    try:
        if len(encoded)>100000: return False
        wire=base64.b64decode(encoded,validate=True)
        handshake=b''; pos=0
        while pos<len(wire):
            if len(wire)-pos<5 or wire[pos]!=22: return False
            size=int.from_bytes(wire[pos+3:pos+5],'big'); pos+=5
            if not 0<size<=18432 or pos+size>len(wire): return False
            handshake+=wire[pos:pos+size]; pos+=size
            if len(handshake)>=4 and len(handshake)>=4+int.from_bytes(handshake[1:4],'big'): break
        if len(handshake)<4 or handshake[0]!=1: return False
        size=int.from_bytes(handshake[1:4],'big')
        if size>65536 or len(handshake)<size+4: return False
        hello=handshake[4:4+size]; pos=34
        def take(n):
            nonlocal pos
            if n<0 or pos+n>len(hello): raise ValueError('Truncated ClientHello')
            result=hello[pos:pos+n]; pos+=n; return result
        def number(n): return int.from_bytes(take(n),'big')
        take(number(1)); ciphers=number(2)
        if ciphers<2 or ciphers%2: return False
        take(ciphers); take(number(1)); extensions=number(2)
        if pos+extensions!=len(hello): return False
        seen=set(); names=[]
        while pos<len(hello):
            kind=number(2); data=take(number(2))
            if kind in seen or kind==0xfe0d: return False  # ECH, including indistinguishable GREASE.
            seen.add(kind)
            if kind==0:
                if len(data)<5 or int.from_bytes(data[:2],'big')!=len(data)-2: return False
                if data[2]!=0 or int.from_bytes(data[3:5],'big')!=len(data)-5: return False
                host=data[5:].decode('ascii')
                import re
                if len(host)>253 or '.' not in host or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in host.split('.')): return False
                names.append(host)
        return len(names)==1
    except (ValueError,IndexError,UnicodeError): return False


def main():
    for line in sys.stdin:
        parts=line.split()
        print('OK' if parts and visible_sni(urllib.parse.unquote(parts[0])) else 'ERR',flush=True)


if __name__=='__main__': main()
