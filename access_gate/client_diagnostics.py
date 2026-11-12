"""Standalone, read-only client path checks. Requires: python -m pip install dnspython."""
import argparse
import datetime as dt
import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit


def get_page(host,address,port,path,context):
    connection=http.client.HTTPSConnection(host,port,timeout=3,context=context)
    try:
        raw=socket.create_connection((address,port),timeout=3)
        try:connection.sock=context.wrap_socket(raw,server_hostname=host)
        except BaseException:raw.close();raise
        connection.request('GET',path,headers={'Host':host,'Connection':'close','User-Agent':'Access-Gate client diagnostic'})
        response=connection.getresponse()
        # Never retain cookies, entry tokens or the page in the report.
        body=response.read(65537)
        if len(body)>65536:raise ValueError('Oversized diagnostic response.')
        return response.status,response.getheader('Location',''),body
    finally:connection.close()


def run_checks(hostname,gateway,portal,*,resolver=None,ca_file=None,port=443):
    import dns.resolver
    hostname=hostname.rstrip('.').encode('idna').decode('ascii').lower()
    if not hostname or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in hostname) or '.' not in hostname:raise ValueError('Use a DNS hostname.')
    gateway=str(ipaddress.IPv4Address(gateway));target=urlsplit(portal)
    if target.scheme!='https' or not target.hostname or target.username or target.password or target.query or target.fragment or target.path not in ('','/'):raise ValueError('Use the configured HTTPS portal origin.')
    result=dict(format=1,checked_at=dt.datetime.now(dt.timezone.utc).isoformat(),resolver_scope='explicit override' if resolver else 'system DNS configuration',trust_scope='additional CA file' if ca_file else 'Python system trust store',layers=[],scope='Results from this client process, not proof of browser Secure DNS, browser CA trust or VPN enforcement. No codes were redeemed.')
    def row(layer,state,guidance):result['layers'].append(dict(layer=layer,state=state,guidance=guidance))
    dns_client=dns.resolver.Resolver()
    if resolver:dns_client.nameservers=[str(ipaddress.ip_address(resolver))]
    for kind in ('A','AAAA','HTTPS','SVCB'):
        try:
            answer=dns_client.resolve(hostname,kind,lifetime=3,raise_on_no_answer=False,search=False)
            values=[str(r) for r in answer] if answer.rrset is not None else []
            good=set(values)=={gateway} if kind=='A' else not values
            row('DNS '+kind,'healthy' if good else 'failed','Expected gateway answer.' if good and kind=='A' else ('Expected local NODATA.' if good else 'Wrong/stale resolver answer. Check client DNS, browser Secure DNS, IPv6 and Pi-hole local mappings; reconnect/clear the client cache.'))
        except dns.resolver.NXDOMAIN:row('DNS '+kind,'failed','Name is NXDOMAIN. Check local mapping and remove conflicting gravity blocking.')
        except Exception:row('DNS '+kind,'unknown','Resolver unavailable or query timed out. Check DNS routing and allowed UDP/TCP 53.')
    try:
        with socket.create_connection((gateway,port),timeout=3):pass
        row('Network','healthy','Configured gateway TCP listener is reachable.')
    except OSError:
        row('Network','failed','Gateway TCP 443 is unreachable/refused. Check VPN routing, firewall policy and HTTPS listener.')
        row('TLS','unknown','Not tested because the listener is unreachable.');row('Gateway','unknown','Not tested.');row('Portal','unknown','Not tested.')
        result['success']=False;return result
    context=ssl.create_default_context(cafile=ca_file)
    try:
        status,location,body=get_page(hostname,gateway,port,'/',context)
        row('TLS','healthy','Verified certificate chain and requested hostname. Confirm trust independently in the browser.')
    except ssl.SSLCertVerificationError:
        row('TLS','failed','CA/hostname validation failed. Install and trust the correct device CA; check clock and requested name. Never disable certificate verification.')
        row('Gateway','unknown','Not tested.');row('Portal','unknown','Not tested.');result['success']=False;return result
    except (OSError,ValueError,http.client.HTTPException):
        row('TLS','failed','TLS/HTTP exchange failed. Check gateway policy freshness, hostname/SNI and service logs.')
        row('Gateway','unknown','Not tested.');row('Portal','unknown','Not tested.');result['success']=False;return result
    destination=urlsplit(location)
    good=status in (302,303,307) and (destination.scheme,destination.hostname,destination.port or 443)==(target.scheme,target.hostname,target.port or 443) and destination.path in ('','/') and destination.query.startswith('entry=') and not destination.username and not destination.fragment
    row('Gateway','healthy' if good else 'failed','Unauthenticated entry redirect points to the configured portal.' if good else 'Expected code-entry redirect was not received. Check domain policy, IP exclusions and gateway/portal configuration.')
    if good:
        try:
            status,_,body=get_page(target.hostname,target.hostname,target.port or 443,(destination.path or '/')+'?'+destination.query,context)
            good_portal=status==200 and b'id="code"' in body
            row('Portal','healthy' if good_portal else 'failed','Code-entry page reached over verified HTTPS.' if good_portal else 'Code-entry page was not returned. Check portal reachability, exclusions and application service.')
        except ssl.SSLCertVerificationError:row('Portal','failed','Portal TLS trust failed. Check the portal certificate and client trust store.')
        except (OSError,ValueError,http.client.HTTPException):row('Portal','failed','Portal is unreachable or returned an invalid response. Check its DNS, HTTPS listener and application.')
    else:row('Portal','unknown','Not followed because the redirect destination was not validated.')
    result['success']=all(r['state']=='healthy' for r in result['layers'])
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hostname',required=True);parser.add_argument('--gateway',required=True);parser.add_argument('--portal',required=True)
    parser.add_argument('--resolver',help='Optional diagnostic DNS override; does not prove the system DNS path.')
    parser.add_argument('--ca',help='Optional additional CA file; does not prove browser trust.')
    args=parser.parse_args()
    try:result=run_checks(args.hostname,args.gateway,args.portal,resolver=args.resolver,ca_file=args.ca)
    except ImportError:parser.exit(2,'Install the client dependency: python -m pip install dnspython\n')
    except (OSError,ValueError):parser.exit(2,'Invalid client settings or unavailable CA file. Check the supplied hostname, IPv4 gateway, HTTPS portal and optional CA path.\n')
    print(json.dumps(result,indent=2));return 0 if result['success'] else 1


if __name__=='__main__':raise SystemExit(main())
