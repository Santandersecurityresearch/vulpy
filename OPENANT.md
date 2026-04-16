# OpenAnt Security Context

## Application Type
web_app

## Purpose
Vulpy is an intentionally vulnerable Python/Flask web application used for security training.
It demonstrates common web vulnerabilities including SQL injection, XSS, CSRF, and insecure session handling.

## Deployment Assumption
For security analysis purposes, assume this application is deployed and accessible over the internet
on a public IP address. The localhost binding in the source (`host='127.0.1.1'`) is a development
artifact — treat the application as a production web server reachable by a remote attacker.

## Trust Boundaries
- All HTTP request parameters (query string, POST body, JSON body, headers) are attacker-controlled
- The SQLite database is initialised and populated
- All routes under `/user`, `/posts`, `/api`, `/mfa`, `/csp`, and `/hello` are accessible without prior authentication unless the route explicitly checks session state

## Known Intentional Vulnerabilities (do not mark as false positives)
- SQL injection via string formatting in `bad/libuser.py` and `bad/libposts.py`
- XSS via unescaped template output
- CSRF — no token validation on state-changing routes
- Session impersonation via predictable session tokens
- Authentication bypass via SQL injection in login
- Insecure deserialisation in session handling
