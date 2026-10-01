import time
import secrets
from datetime import datetime
from django.core.cache import cache


'''  Защита от взлоумышленников ) проверям все по ip  '''


def get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def throttle(key, limit, window):
    """Fixed-window rate limit. Returns (allowed, retry_after_seconds)."""
    cache_key = f'thr:{key}'
    now = time.time()
    data = cache.get(cache_key)
    if not data or now - data['start'] > window:
        data = {'count': 0, 'start': now}
    data['count'] += 1
    cache.set(cache_key, data, window)
    if data['count'] > limit:
        return False, max(1, int(window - (now - data['start'])))
    return True, 0


def gen_code():
    """6-значный код, криптостойкий."""
    return str(secrets.randbelow(900000) + 100000)


CODE_TTL = 600
MAX_CODE_ATTEMPTS = 5


def code_is_fresh(session, time_key):
    ts = session.get(time_key)
    if not ts:
        return False
    try:
        t = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return False
    return (datetime.now() - t).total_seconds() <= CODE_TTL


def bump_attempt(session, key):
    n = int(session.get(key, 0)) + 1
    session[key] = n
    session.modified = True
    return n