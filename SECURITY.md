# Security policy

## Supported versions

Only the latest tagged release is actively maintained. Pre-1.0 series ships
fixes on the `main` branch; downstream deployers should pull the latest
docker tag.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Email: security@nks-hub.cz (preferred) or open a private security advisory
via GitHub's "Security" tab on this repository.

Include:

- A description of the vulnerability
- Steps to reproduce (proof of concept if possible)
- Expected impact / affected endpoints
- Your suggested fix, if any

We aim to acknowledge within 72 hours and to ship a fix within 14 days for
critical issues, 30 days for high severity, and best-effort for lower
severity findings. Coordinated disclosure is appreciated.

## Hardening notes for operators

- Set `NKS_WDC_JWT_SECRET` and `NKS_WDC_SESSION_SECRET` to independent
  random 32+ byte values before exposing the service publicly.
- Never leave `NKS_WDC_CATALOG_DEV=1` on a public instance.
- Run behind a TLS-terminating reverse proxy with HSTS.
- Mount the SQLite state volume on an encrypted filesystem until
  payload-level encryption (planned, see roadmap) ships.
- Restrict `/admin/*` at the reverse-proxy layer to known IPs / SSO
  until role-based access control lands.
