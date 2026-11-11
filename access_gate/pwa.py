"""Small self-contained install assets; no generated binary files in the source tree."""
import struct
import zlib


def icon(size):
    # An original high-contrast AG monogram on the existing portal palette.
    letters=('01110011110','11011011000','11011011000','11111011011','11011011001','11011011111','11011001110')
    def chunk(kind,data):return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data)&0xffffffff)
    cell=size//16;left=(size-11*cell)//2;top=(size-7*cell)//2;rows=[]
    for y in range(size):
        row=bytearray(b'\0')
        for x in range(size):
            xx=(x-left)//cell;yy=(y-top)//cell
            lit=0<=xx<11 and 0<=yy<7 and letters[yy][xx]=='1'
            row.extend((164,184,255) if lit else (16,22,36))
        rows.append(bytes(row))
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',size,size,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows)))+chunk(b'IEND',b'')
