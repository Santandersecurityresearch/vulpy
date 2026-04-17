import sqlite3
import logging
from flask import Blueprint, render_template, render_template_string, redirect, request, g

import libposts
import libuser

# CWE-94 / CWE-1336: Server-Side Template Injection
# Inspired by Log4Shell (CVE-2021-44228): user-controlled strings were passed
# to Log4j's logger, which evaluated JNDI lookup expressions like ${jndi:ldap://...}
# before writing them. The Python equivalent is passing user input to
# render_template_string(), which evaluates Jinja2 expressions like {{7*7}} or
# {{config}} — giving full RCE via {{''.__class__.__mro__[1].__subclasses__()}}.
logger = logging.getLogger(__name__)

mod_posts = Blueprint('mod_posts', __name__, template_folder='templates')


@mod_posts.route('/')
@mod_posts.route('/<username>')
def do_view(username=None):

    if not username:
        if 'username' in g.session:
            username = g.session['username']

    posts = libposts.get_posts(username)
    users = libuser.userlist()

    return render_template('posts.view.html', posts=posts, username=username, users=users)


@mod_posts.route('/search')
def do_search():
    query = request.args.get('q', '')
    # VULNERABILITY: user input passed directly to render_template_string().
    # Equivalent to Log4Shell — the "logger" evaluates attacker-controlled content.
    # Try: /posts/search?q={{config}} or {{''.__class__.__mro__[1].__subclasses__()}}
    logger.info('search query from %s: %s', request.remote_addr, query)
    template = '<h2>Search results for: ' + query + '</h2>'   # string concat, not escaping
    return render_template_string(template)


@mod_posts.route('/', methods=['POST'])
def do_create():

    if 'username' not in g.session:
        return redirect('/user/login')

    if request.method == 'POST':

        username = g.session['username']
        text = request.form.get('text')

        libposts.post(username, text)

    return redirect('/')

