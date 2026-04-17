import json
import base64
import hmac
import hashlib

# CWE-347: Improper Verification of Cryptographic Signature
# Inspired by JWT "alg:none" confusion attacks (Auth0, numerous APIs 2022-2023).
# A signed token looks like: b64(header).b64(payload).b64(signature)
# Setting "alg": "none" in the header causes signature verification to be skipped entirely.
JWT_SECRET = 'vulpy-super-secret-key'


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def create(response, username):
    header = _b64url_encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())
    payload = _b64url_encode(json.dumps({'username': username}).encode())
    sig = _b64url_encode(
        hmac.new(JWT_SECRET.encode(), f'{header}.{payload}'.encode(), hashlib.sha256).digest()
    )
    token = f'{header}.{payload}.{sig}'
    response.set_cookie('vulpy_session', token)
    return response


def load(request):

    session = {}
    cookie = request.cookies.get('vulpy_session')

    try:
        if cookie:
            parts = cookie.split('.')
            if len(parts) == 3:
                header = json.loads(_b64url_decode(parts[0]))
                payload = json.loads(_b64url_decode(parts[1]))

                # VULNERABILITY: if the token says alg=none, skip signature verification
                if header.get('alg', '').lower() == 'none':
                    return payload

                expected_sig = _b64url_encode(
                    hmac.new(JWT_SECRET.encode(), f'{parts[0]}.{parts[1]}'.encode(), hashlib.sha256).digest()
                )
                if hmac.compare_digest(parts[2], expected_sig):
                    return payload
            else:
                # legacy base64 JSON fallback
                decoded = base64.b64decode(cookie.encode())
                if decoded:
                    session = json.loads(decoded)
    except Exception:
        pass

    return session


def destroy(response):
    response.set_cookie('vulpy_session', '', expires=0)
    return response

