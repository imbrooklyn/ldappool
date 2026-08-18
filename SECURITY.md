# Security Policy

## Supported versions

Before v1.0.0, only the latest released v0.x version receives security fixes.
After v1.0.0, the latest minor release of the current major version is
supported. Older releases may receive a fix when coordinated disclosure makes
an immediate upgrade impractical, but this is not guaranteed.

## Go toolchain security

The module language floor is Go 1.25.0 because that is the floor of the
selected go-ldap release. It is not a security endorsement of every Go 1.25
patch release. Version 0.1.0-beta.1 is validated with Go 1.25.13 and Go 1.26.6,
the supported security-patched releases current on 2026-08-18. Consumers
compile this library into their own binaries and therefore must keep their Go
toolchain on a supported, current patch release. CI pins known-safe patch
versions and the release checklist runs `govulncheck` with the newest supported
line.

At the 2026-08-18 release scan, `govulncheck` reports no reachable or imported
package vulnerability. It reports [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)
only at the required `golang.org/x/crypto` module level: the advisory concerns
the `openpgp` package, which is not imported or reachable in this module's
production graph, and no fixed module version exists. This residual advisory is
tracked on every dependency review.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security advisory flow for this repository and include:

- affected versions and environment;
- a minimal reproducer or protocol trace with all credentials, DNs, filters,
  attribute values, hostnames, and server diagnostics redacted;
- the expected and observed security boundary;
- any known exploitation prerequisites or impact.

Maintainers should acknowledge a complete report within seven calendar days,
then coordinate validation, severity, remediation, release, and disclosure with
the reporter. Timelines depend on impact and on upstream coordination.

## Scope

Security-sensitive invariants include TLS identity verification, prevention of
shared-connection rebinding, secret and diagnostic redaction, exact write
outcome classification, credential lockout protection, lease invalidation,
connection-count conservation, and bounded shutdown behavior.

The project tracks relevant upstream go-ldap and transitive dependency risks.
Known upstream risks are documented and tested locally; the project does not
promise to file a public upstream issue. When a defect belongs upstream,
coordinated private disclosure may be required before any public reference.

Never include real LDAP credentials or directory data in a report, fixture,
log, packet capture, or benchmark.
