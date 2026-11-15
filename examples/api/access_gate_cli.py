#!/usr/bin/env python3
"""Interactive Access Gate REST API v1 client (Python 3.9+, standard library only)."""
import argparse
import csv
import getpass
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
from urllib import error, parse, request

CONFIG_FILE = Path.home() / '.access-gate-cli.json'
DEFAULT_TIMEOUT = 20


class ApiError(Exception):
    pass


def prompt(message, default=None):
    suffix = f' [{default}]' if default is not None else ''
    value = input(f'{message}{suffix}: ').strip()
    return value if value else default


def positive_int(message, default, maximum):
    while True:
        value = prompt(message, default)
        try:
            number = int(value)
            if 1 <= number <= maximum:
                return number
        except (ValueError, TypeError):
            pass
        print(f'Enter a whole number between 1 and {maximum}.')


def load_config():
    try:
        return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}
    except (ValueError, OSError) as exc:
        raise ApiError(f'Cannot read {CONFIG_FILE}: {exc}') from exc


def save_config(config):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(prefix='.access-gate-', dir=str(CONFIG_FILE.parent))
    try:
        if os.name == 'posix':
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(config, stream, indent=2)
            stream.write('\n')
        os.replace(tmpname, CONFIG_FILE)
    finally:
        if os.path.exists(tmpname):
            os.unlink(tmpname)


def normalize_url(value):
    value = value.strip().rstrip('/')
    parsed = parse.urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ApiError('Use the canonical HTTPS portal origin, e.g. https://gate.example.com (no path or query).')
    return value


class AccessGate:
    def __init__(self, base_url, key):
        self.base_url = normalize_url(base_url)
        self.key = key
        # Disable redirects so the bearer token cannot be forwarded elsewhere.
        class NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        self.opener = request.build_opener(NoRedirect())

    def call(self, method, path, payload=None, params=None, idem_key=None):
        url = self.base_url + '/api/v1' + path
        if params:
            url += '?' + parse.urlencode(params)
        data = None if payload is None else json.dumps(payload, separators=(',', ':')).encode('utf-8')
        headers = {'Authorization': 'Bearer ' + self.key, 'Accept': 'application/json'}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        if idem_key is not None:
            headers['Idempotency-Key'] = idem_key
        req = request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=DEFAULT_TIMEOUT) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                raise ApiError('Server redirected the request. Configure the exact canonical HTTPS portal address.') from exc
            try:
                detail = json.loads(exc.read().decode('utf-8'))
                item = detail.get('error', {})
                msg = f"{item.get('code', 'error')}: {item.get('message', 'Request failed')}"
                if item.get('details'):
                    msg += ' | ' + '; '.join(d.get('message', '') for d in item['details'])
            except (ValueError, UnicodeError, AttributeError):
                msg = exc.reason
            hint = {
                401: 'Check your API key.',
                403: 'Check API scopes and allowed source IP/CIDR.',
                404: 'Check whether API integrations are enabled and the URL is canonical.',
                429: 'API rate limit reached; try again later.',
            }.get(exc.code, '')
            raise ApiError(f'HTTP {exc.code} — {msg}. {hint}'.strip()) from exc
        except error.URLError as exc:
            raise ApiError(f'Connection/TLS error: {exc.reason}. Verify the portal hostname and trusted CA.') from exc
        except (TimeoutError, json.JSONDecodeError) as exc:
            raise ApiError(f'Network or response error: {exc}') from exc

    def paginate(self, path):
        cursor = None
        seen_cursors = set()
        items = []
        while True:
            params = {'page_size': 100}
            if cursor:
                params['cursor'] = cursor
            result = self.call('GET', path, params=params)
            items.extend(result.get('items', []))
            cursor = result.get('next_cursor')
            if not cursor:
                return items
            if cursor in seen_cursors:
                raise ApiError('API returned a repeating pagination cursor.')
            seen_cursors.add(cursor)


def print_json(data):
    print(json.dumps(data, indent=2, ensure_ascii=False))


def export_codes(result):
    codes = result.get('codes', [])
    if not codes:
        print('No raw codes were returned.')
        return
    filename = f"access-gate-{result['batch_id']}.csv"
    destination = Path(prompt('Export CSV file', filename)).expanduser().resolve()
    if destination.exists() and prompt('File exists. Overwrite? (yes/no)', 'no').lower() != 'yes':
        print('Export cancelled.')
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if os.name == 'posix':
        flags |= os.O_NOFOLLOW if hasattr(os, 'O_NOFOLLOW') else 0
    fd = os.open(str(destination), flags, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['batch_id', 'code_id', 'code', 'valid_until', 'access_seconds'])
            for entry in codes:
                writer.writerow([result['batch_id'], entry['id'], entry['code'], result.get('valid_until', ''), result.get('access_seconds', '')])
    except Exception:
        raise
    print(f'Saved {len(codes)} secret codes to {destination}. Keep this file private.')


def create_batch(api):
    print('\nCreate batch (press Enter for a default)')
    name = prompt('Batch name', '')
    count = positive_int('Number of codes', '10', 1000)
    validity_unit = choose('Code validity unit', ['days', 'hours'], 1)
    validity_max = 365 if validity_unit == 'days' else 8760
    validity = positive_int('Code validity', '7' if validity_unit == 'days' else '168', validity_max)
    access_unit = choose('Access duration unit', ['minutes', 'hours'], 1)
    access_max = 10080 if access_unit == 'minutes' else 168
    access = positive_int('Access per redemption', '15' if access_unit == 'minutes' else '1', access_max)
    payload = {'count': count, 'validity_value': validity, 'validity_unit': validity_unit,
               'access_value': access, 'access_unit': access_unit}
    if name:
        payload['name'] = name
    print('\nCreation settings:')
    print_json(payload)
    if prompt('Create this batch? (yes/no)', 'no').lower() != 'yes':
        return
    idem = secrets.token_hex(24)
    # Preserve retry inputs if the connection drops after the server commits.
    pending = CONFIG_FILE.with_name('.access-gate-pending.json')
    if pending.exists():
        print(f'Unresolved previous creation exists: {pending}. Resolve it before creating another batch.')
        return
    with os.fdopen(os.open(str(pending), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='utf-8') as stream:
        json.dump({'url': api.base_url, 'payload': payload, 'idempotency_key': idem, 'created': time.time()}, stream)
    try:
        result = api.call('POST', '/batches', payload, idem_key=idem)
    except ApiError:
        print(f'Creation outcome may be uncertain. Retry from menu using {pending} (same key and body).')
        raise
    pending.unlink(missing_ok=True)
    print(f"Created batch {result['batch_id']} — {result['count']} codes")
    print(f"Valid until: {result.get('valid_until', '?')}")
    export_codes(result)
    print('Full codes cannot be retrieved later via normal reads.')


def retry_pending(api):
    pending = CONFIG_FILE.with_name('.access-gate-pending.json')
    if not pending.exists():
        print('No pending creation.')
        return
    obj = json.loads(pending.read_text(encoding='utf-8'))
    if obj['url'] != api.base_url:
        print('Pending operation targets a different portal. Change the configured address first.')
        return
    if time.time() - obj.get('created', 0) > 24 * 3600:
        print('The 24-hour replay window may have ended. Reconcile the original batch in the admin portal. Not retrying.')
        return
    print('This retries the exact original batch operation; it will not intentionally create another batch.')
    if prompt('Retry? (yes/no)', 'no').lower() != 'yes':
        return
    result = api.call('POST', '/batches', obj['payload'], idem_key=obj['idempotency_key'])
    pending.unlink(missing_ok=True)
    print(f"Recovered batch {result['batch_id']}")
    export_codes(result)


def choose(label, choices, default=None):
    print(label + ':')
    for number, item in enumerate(choices, 1):
        print(f'  {number}. {item}')
    while True:
        raw = prompt('Choice', str(default) if default else None)
        try:
            idx = int(raw)
            if 1 <= idx <= len(choices):
                return choices[idx - 1]
        except (TypeError, ValueError):
            pass
        print('Choose one of the listed numbers.')


def show_batches(api):
    items = api.paginate('/batches')
    if not items:
        print('No batches owned by this API credential.')
        return
    print(f'\n{len(items)} batches:')
    for item in items:
        print(f"{item.get('id', item.get('batch_id', '?')):18} | {item.get('name', '')} | {item.get('status', '')} | {item.get('created_at', '')}")


def batch_id():
    return prompt('Batch ID')


def batch_details(api):
    value = batch_id()
    if value:
        print_json(api.call('GET', '/batches/' + parse.quote(value, safe='')))


def batch_codes(api):
    value = batch_id()
    if value:
        items = api.paginate('/batches/' + parse.quote(value, safe='') + '/codes')
        print_json(items)
        print(f'{len(items)} code records (full secret codes intentionally unavailable).')


def revoke_batch(api):
    value = batch_id()
    if value and prompt(f'Type REVOKE to revoke the entire batch {value}', '') == 'REVOKE':
        print_json(api.call('POST', '/batches/' + parse.quote(value, safe='') + '/revoke', {}))


def revoke_code(api):
    value = prompt('Code ID (not the secret code text)')
    if value and prompt(f'Type REVOKE to revoke code {value}', '') == 'REVOKE':
        print_json(api.call('POST', '/codes/' + parse.quote(value, safe='') + '/revoke', {}))


def main():
    parser = argparse.ArgumentParser(description='Access Gate API v1 management CLI')
    parser.add_argument('--key', help='API credential (avoid command-line history; interactive prompt is safer)')
    parser.add_argument('--url', help='Canonical HTTPS portal origin; saves locally for future runs')
    args = parser.parse_args()
    config = load_config()
    if args.url:
        config['url'] = normalize_url(args.url)
        save_config(config)
    if not config.get('url'):
        config['url'] = normalize_url(prompt('First-time setup — canonical Access Gate HTTPS portal URL'))
        save_config(config)
    print('Portal:', config['url'])
    key = args.key or os.environ.get('ACCESS_GATE_API_KEY') or getpass.getpass('Access Gate API key (hidden): ').strip()
    if not key:
        raise ApiError('An API key is required.')
    api = AccessGate(config['url'], key)
    menu = [
        ('Create a batch', create_batch),
        ('List batches', show_batches),
        ('Read a batch', batch_details),
        ('Read codes in a batch', batch_codes),
        ('Revoke one code', revoke_code),
        ('Revoke a batch', revoke_batch),
        ('Retry an uncertain creation', retry_pending),
    ]
    while True:
        print('\n=== Access Gate CLI ===')
        for i, (label, _) in enumerate(menu, 1):
            print(f' {i}. {label}')
        print(' 0. Exit')
        choice = prompt('Select', '0')
        if choice == '0':
            return
        if choice.isdecimal() and 1 <= int(choice) <= len(menu):
            try:
                menu[int(choice)-1][1](api)
            except ApiError as exc:
                print('ERROR:', exc, file=sys.stderr)
        else:
            print('Invalid choice.')


if __name__ == '__main__':
    try:
        main()
    except (ApiError, KeyboardInterrupt, EOFError) as exc:
        print(f'\n{exc or "Cancelled"}', file=sys.stderr)
        sys.exit(1)
