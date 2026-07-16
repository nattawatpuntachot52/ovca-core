# Security Policy

GitHub private vulnerability reporting is the preferred channel when it is
enabled for this repository.

If it is unavailable, open a minimal public issue asking maintainers to provide
a private contact channel. Do not include vulnerability details, credentials,
personal data, or private paths in the issue.

After publication, maintainers should enable GitHub private vulnerability
reporting for this repository.

OVCA Core is a local development runtime. It has no authorization layer for
exposure to untrusted networks. Bind services to loopback or place them behind
an independently reviewed authentication and network boundary.
