# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha] - 2026-08-16

### Added

- Lazy, fixed-identity LDAP connection pool with FIFO callback-scoped leases.
- Verified LDAPS and StartTLS, explicit anonymous mode, and guarded
  development-only plaintext authentication.
- Synchronous Search, SearchWithPaging, DirSync, Compare, Add, Modify, Delete,
  ModifyDN, and PasswordModify operations.
- Context cancellation, operation deadlines, transport eviction, precise write
  outcome classification, and no automatic operation retries.
- Connection and credential exponential backoff with jitter, process-local
  credential protection, half-open probing, and password rotation.
- Idle-time and lifetime eviction, bounded waiter and connection counts,
  graceful Close, and ForceClose.
- Passive redacted snapshots and an optional bounded asynchronous observer.
- Deterministic protocol, TLS, concurrency, race, fuzz, API-surface, dependency,
  and benchmark test suites.

### Security

- Raw LDAP clients and session-changing methods are deliberately absent.
- Passwords and raw server diagnostics are excluded from public errors, events,
  snapshots, and string formatting.
- Release validation pins the security-patched Go 1.25.13 and Go 1.26.6
  toolchains and includes reachable-code vulnerability scanning.
- The release scan has no reachable or imported-package vulnerabilities;
  module-only GO-2026-5932 is documented as an unreachable residual risk.

[Unreleased]: https://github.com/imbrooklyn/ldappool/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/imbrooklyn/ldappool/releases/tag/v0.1.0-alpha
