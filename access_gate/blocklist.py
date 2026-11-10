"""Bounded public-HTTPS blocklist downloads and hosts/domain-list parsing."""
import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

from .core import GateError
from .dns_export import hostname, MAX_DOMAINS

MAX_BYTES = 32 * 1024 * 1024
DOWNLOAD_SECONDS = 10
SOCKET_SECONDS = 4
LOCAL_SUFFIXES = ('.localhost', '.localdomain', '.local', '.lan', '.internal', '.home.arpa')


def source_url(value):
    try:
        if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in value): raise ValueError()
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443) or parsed.fragment: raise ValueError()
        host = hostname(parsed.hostname or '')
        path = parsed.path or '/'
        # HTTP request targets must remain ASCII. Internationalized hosts are normalized above.
        target = path + ('?' + parsed.query if parsed.query else '')
        target.encode('ascii')
        if not target.startswith('/') or host.endswith(LOCAL_SUFFIXES): raise ValueError()
        return host, target
    except (ValueError, UnicodeError):
        raise GateError('Use a public HTTPS text-list URL without credentials, a fragment or a custom port.')


def public_addresses(host):
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
        if not addresses: raise ValueError()
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if '%' in address or not ip.is_global or ip.is_multicast or ip.is_reserved: raise ValueError()
        return addresses
    except (OSError, ValueError):
        raise GateError('The source must resolve only to public Internet addresses. Local/private targets are not allowed.')


class PublicHTTPSConnection(http.client.HTTPSConnection):
    """Pin the approved destination while keeping TLS/SNI verification on the hostname."""
    def __init__(self, host, address, timeout):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self.approved_address = address

    def connect(self):
        raw = socket.create_connection((self.approved_address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def download_blocklist(url):
    deadline = time.monotonic() + DOWNLOAD_SECONDS

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0: raise GateError('The blocklist download timed out. Nothing was imported.')
        return min(left, SOCKET_SECONDS)

    for hop in range(4):
        host, target = source_url(url)
        addresses = public_addresses(host)
        connection = None
        response = None
        try:
            # A numeric, previously checked address is used for connect; no DNS re-resolution.
            connection = PublicHTTPSConnection(host, addresses[0], remaining())
            connection.request('GET', target, headers={'User-Agent': 'Access-Gate blocklist importer',
                'Accept': 'text/plain, application/octet-stream;q=0.9', 'Accept-Encoding': 'identity'})
            if connection.sock is not None: connection.sock.settimeout(remaining())
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if not location or hop == 3: raise GateError('The source redirected too many times or without a destination.')
                url = urljoin(url, location)
                continue
            if response.status != 200: raise GateError(f'The source returned HTTP {response.status}. Nothing was imported.')
            content_type = response.getheader('Content-Type', '').split(';', 1)[0].lower().strip()
            if content_type in ('text/html', 'application/xhtml+xml'):
                raise GateError('The URL returned a web page. Use the raw text/hosts file URL.')
            if response.getheader('Content-Encoding', 'identity').lower().strip() not in ('', 'identity'):
                raise GateError('The source returned compressed content despite the plain-text request.')
            length = response.getheader('Content-Length')
            if length is not None:
                try: length = int(length)
                except ValueError: raise GateError('The source returned an invalid download length.')
                if length < 0 or length > MAX_BYTES: raise GateError('The blocklist exceeds the 32 MiB download limit.')
            data = bytearray()
            while True:
                if connection.sock is not None: connection.sock.settimeout(remaining())
                remaining()
                chunk = response.read1(min(65536, MAX_BYTES + 1 - len(data)))
                if not chunk: break
                data.extend(chunk)
                if len(data) > MAX_BYTES: raise GateError('The blocklist exceeds the 32 MiB download limit.')
            if length is not None and len(data) != length:
                raise GateError('The blocklist download was incomplete. Nothing was imported.')
            try: return data.decode('utf-8-sig')
            except UnicodeError: raise GateError('Use a UTF-8 plain-text hosts or domain list.')
        except (OSError, http.client.HTTPException) as exc:
            raise GateError('Could not download the blocklist over verified HTTPS. Nothing was imported.') from exc
        finally:
            if response is not None: response.close()
            if connection is not None: connection.close()
    raise GateError('The source redirected too many times.')


def parse_blocklist(text, scope='subdomains'):
    if scope not in ('subdomains', 'exact'): raise GateError('Choose a valid domain match scope.')
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_BYTES:
        raise GateError('The blocklist exceeds the 32 MiB text limit.')
    if '\x00' in text or '<html' in text[:4096].lower() or '<!doctype html' in text[:4096].lower():
        raise GateError('The source is not a plain-text blocklist. Use the raw text/hosts URL.')
    names = set(); duplicates = skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '!', '[Adblock')): continue
        line = line.split('#', 1)[0].strip()
        fields = line.split()
        if not fields: continue
        try: ipaddress.ip_address(fields[0]); candidates = fields[1:]
        except ValueError:
            if len(fields) != 1:
                skipped += 1; continue
            candidate = fields[0]
            if candidate.startswith('||') and candidate.endswith('^'):
                candidate = candidate[2:-1]
            candidates = [candidate]
        if not candidates: skipped += 1
        for candidate in candidates:
            if scope == 'subdomains': candidate = candidate.removeprefix('*.')
            try:
                name = hostname(candidate)
                if name.endswith(LOCAL_SUFFIXES): raise GateError('Local hostname.')
            except GateError:
                skipped += 1; continue
            if name in names: duplicates += 1
            names.add(name)
            if len(names) > MAX_DOMAINS: raise GateError(f'The source exceeds the {MAX_DOMAINS:,} unique-domain limit.')
    if not names: raise GateError('No supported public domain entries were found. Nothing was imported.')
    return dict(domains=names, duplicates=duplicates, skipped=skipped)
