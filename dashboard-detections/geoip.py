import ipaddress
import json
import threading
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

BATCH_API = 'http://ip-api.com/batch?fields=query,country,countryCode,status'
SINGLE_API = 'http://ip-api.com/json/{}?fields=query,country,countryCode,status'

_cache = {}
_cache_lock = threading.Lock()
_cache_ttl = 3600
_last_batch = 0
_min_batch_interval = 60


def _classify(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return 'Loopback', 'LO'
        if addr.is_private:
            return 'Private', 'PR'
        if addr.is_link_local:
            return 'Link-local', 'LL'
        if addr.is_multicast:
            return 'Multicast', 'MC'
        if addr.is_unspecified:
            return 'Unspecified', 'UN'
        return None, None
    except ValueError:
        return 'Invalid', '??'


def _resolve_single(ip_str):
    try:
        req = Request(SINGLE_API.format(ip_str), headers={'User-Agent': 'DashboardMenace/1.0'})
        with urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get('status') == 'success':
            return data.get('country', 'Unknown'), data.get('countryCode', '')
    except (URLError, HTTPError, json.JSONDecodeError, OSError):
        pass
    return None, None


def _resolve_batch(ips):
    global _last_batch
    now = time.time()
    if now - _last_batch < _min_batch_interval:
        return {}

    try:
        body = json.dumps([{'query': ip.strip(), 'fields': 'query,country,countryCode,status'} for ip in ips]).encode()
        req = Request(BATCH_API, data=body, headers={
            'User-Agent': 'DashboardMenace/1.0',
            'Content-Type': 'application/json',
        })
        with urlopen(req, timeout=5) as resp:
            results = json.loads(resp.read().decode())
        _last_batch = time.time()
        out = {}
        for r in results:
            if r.get('status') == 'success':
                out[r['query']] = (r.get('country', 'Unknown'), r.get('countryCode', ''))
        return out
    except (URLError, HTTPError, json.JSONDecodeError, OSError):
        return {}


def resolve(ip_str):
    ip_str = str(ip_str).strip()

    name, code = _classify(ip_str)
    if name:
        return name, code

    with _cache_lock:
        cached = _cache.get(ip_str)
        if cached and (time.time() - cached['ts']) < _cache_ttl:
            return cached['country'], cached.get('code', '')

    country, code = _resolve_single(ip_str)

    with _cache_lock:
        _cache[ip_str] = {'country': country or 'Unknown', 'code': code or '', 'ts': time.time()}

    return country or 'Unknown', code or ''


def resolve_batch(ip_list):
    unique = list(set(ip_list))
    results = {}

    unresolved = []
    now = time.time()

    with _cache_lock:
        for ip in unique:
            name, code = _classify(ip)
            if name:
                results[ip] = (name, code)
                continue
            cached = _cache.get(ip)
            if cached and (now - cached['ts']) < _cache_ttl:
                results[ip] = (cached['country'], cached.get('code', ''))
            else:
                unresolved.append(ip)

    if unresolved:
        batch_results = _resolve_batch(unresolved)
        for ip in unresolved:
            if ip in batch_results:
                country, code = batch_results[ip]
            else:
                country, code = _resolve_single(ip)

            with _cache_lock:
                _cache[ip] = {'country': country or 'Unknown', 'code': code or '', 'ts': time.time()}

            results[ip] = (country or 'Unknown', code or '')

    return results
