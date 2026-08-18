# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.1] - 2026-08-20

### Added

- Define explicit beta, RC, and final v0.1.0 entry gates and compatibility
  promises.
- Add direct tests for the alpha.2 `CredentialGuard` API and critical
  connection-completion and shutdown transitions.

### Fixed

- Make the vulnerability scan use the already configured Go toolchain and a
  pinned scanner, avoiding the duplicate Go cache restore that made the
  release gate fail after the product tests had passed.
- Add one stable aggregate CI check and a signed-tag release workflow so a
  release candidate cannot be treated as publishable before all gates pass.
- Publish the successful aggregate result as both a GitHub Actions check and a
  GitHub Actions-authenticated commit status, allowing protected direct pushes
  to enforce the same exact-candidate gate without a pull request.

### Changed

- Define a solo-maintainer direct-release path: pull-request approval is not
  required, while exact-candidate and `main` CI plus the signed-tag Release
  Gate remain mandatory.

### Documentation

- Record completed `v0.1.0-alpha.2` validation in a real Microsoft Active
  Directory test environment and clarify the public evidence boundary.
- Document request and custom-control ownership during synchronous operations.

## [0.1.0-alpha.2] - 2026-08-18

### Added

- Add `CredentialGuard` for sharing one simple-Bind identity, password,
  credential generation, global Bind single-flight, classifier, and failure
  state across pools.

### Fixed

- Accept an optional matching StartTLS `responseName` while continuing to
  reject a mismatched OID or any StartTLS `responseValue`.
- Recognize LDAP unsolicited notifications and preserve an already confirmed
  operation result when a Notice of Disconnection follows it.
- Retire connections already known closed by the go-ldap reader before idle
  handoff.

### Changed

- Remove the unused legacy credential classifier path.

## [0.1.0-alpha.1] - 2026-08-17

### Fixed

- Strictly validate Bind and operation response tags, complete LDAPResult
  structure, untruncated result codes, and operation-specific success codes.
- Preserve credential protection when a Bind result is followed by malformed
  response controls.
- Serialize credential resets with waiter gate decisions so stale blocked
  state cannot reject an acquisition after manual reset or password rotation.
- Evict connections already closed by the LDAP reader while preserving
  `ErrNotSent` for an operation that wrote no request bytes.
- Preserve `runtime.Goexit` control flow while retiring the interrupted lease.

### Changed

- Describe the prerelease as alpha/experimental and clarify that credential
  guard state is per-pool rather than process-wide.

## [0.1.0-alpha] - 2026-08-16

### Added

- Lazy, fixed-identity LDAP connection pool with FIFO callback-scoped leases.
- Verified LDAPS and StartTLS, explicit anonymous mode, and guarded
  development-only plaintext authentication.
- Synchronous Search, SearchWithPaging, DirSync, Compare, Add, Modify, Delete,
  ModifyDN, and PasswordModify operations.
- Context cancellation, operation deadlines, transport eviction, precise write
  outcome classification, and no automatic operation retries.
- Connection and credential exponential backoff with jitter, per-pool
  in-process credential protection, half-open probing, and password rotation.
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

[Unreleased]: https://github.com/imbrooklyn/ldappool/compare/v0.1.0-beta.1...HEAD
[0.1.0-beta.1]: https://github.com/imbrooklyn/ldappool/compare/v0.1.0-alpha.2...v0.1.0-beta.1
[0.1.0-alpha.2]: https://github.com/imbrooklyn/ldappool/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/imbrooklyn/ldappool/compare/v0.1.0-alpha...v0.1.0-alpha.1
[0.1.0-alpha]: https://github.com/imbrooklyn/ldappool/releases/tag/v0.1.0-alpha
