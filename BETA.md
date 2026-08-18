# v0.1.0 prerelease contract

This document defines the entry and compatibility contract for the remaining
v0.1.0 prereleases. The current release is `v0.1.0-beta.1`; its beta label does
not recommend it for production use.

## Validation evidence

On 2026-08-18, `v0.1.0-alpha.2` completed end-to-end validation in a real
Microsoft Active Directory test environment. No credentials, directory data,
hostnames, or other environment-specific values are stored in this repository.
`v0.1.0-beta.1` changes tests, documentation, and release automation only, so
it retains the production-package behavior covered by that validation.

The public record currently identifies the server family and completion date,
but not the AD DS build, topology, policy configuration, or case-by-case result
matrix. The result is therefore evidence of real-environment interoperability,
not certification of every Active Directory version or deployment topology.
OpenLDAP and 389 Directory Server have not yet been recorded as
real-environment validation targets.

The repeatable repository suite remains infrastructure-independent. It uses
`net.Pipe`, in-memory certificates, scripted BER peers, race tests, fuzzing, and
cross-builds so that pull requests do not depend on access to an external
directory.

## Beta scope

A beta candidate makes the following bounded claims:

- Go 1.25 language compatibility, validated with the exact Go 1.25.13 and Go
  1.26.6 toolchains. Cross-compilation is checked for Linux amd64/arm64 and
  Windows amd64; that check is not a runtime certification of those platforms.
- LDAP, LDAPS, and StartTLS transport policies with verified TLS by default;
  plaintext simple Bind remains an explicit development-only exception.
- Explicit anonymous authentication or one fixed simple-Bind identity, with an
  optional `CredentialGuard` shared across pools for that identity.
- The synchronous `Search`, `SearchWithPaging`, `DirSync`, `Compare`, `Add`,
  `Modify`, `Del`, `ModifyDN`, and `PasswordModify` methods documented in
  `README.md`. Raw clients, rebinding, session-state changes, streaming, and
  generic extended operations remain outside the surface.
- Callback-scoped leases, FIFO bounded acquisition, exact open-connection
  accounting, no automatic operation retry, explicit write-delivery outcomes,
  credential-generation retirement, bounded shutdown, and redacted passive
  observability as documented in `README.md` and GoDoc.

The exported API is the surface locked by `api_test.go`; examples or upstream
go-ldap methods do not extend it implicitly.

## Beta entry gate

A `v0.1.0-beta.N` tag may be published only when all of the following are true
for the tagged commit:

1. The exact commit is on `main`, its complete diff has been reviewed by the
   maintainer, and it has passed `CI / required` both as a candidate and on
   `main`. A pull request or independent approval is not required for this
   solo-maintainer repository.
2. Go 1.25.13 and Go 1.26.6 both pass module verification, tidy and formatting
   checks, vet, 20 repeated test runs, and at least 85% statement coverage.
3. Go 1.26.6 additionally passes `-race -count=10`, all five fuzz targets, and
   a text-mode `govulncheck ./...` scan with no reachable vulnerability.
4. Linux amd64, Linux arm64, and Windows amd64 test binaries cross-compile.
5. Every exported API added after `v0.1.0-alpha.1` has a direct test. Critical
   credential, connect-completion, lease-retirement, and shutdown transitions
   have deterministic tests that assert their terminal state and counters.
6. The real Active Directory validation above remains applicable to the beta
   candidate, or is rerun when a change affects TLS, Bind, LDAP wire handling,
   operation behavior, or credential lifecycle.
7. The exported API, documented errors and delivery outcomes, request ownership
   rules, snapshot counters, and shutdown behavior agree with the implementation.
8. `CHANGELOG.md`, dependency notices, version references, and known limitations
   are current. The release tag is annotated, signed, and GitHub-verified.
9. The tag-triggered `Release Gate / release-ready` check succeeds before a
   GitHub Release is created. A rerun may repair infrastructure failure, but no
   failing product or security check may be waived silently.

## Beta compatibility promise

Within the `v0.1.0-beta.*` series, additions and compatible corrections are
expected. An incompatible correction is allowed only for security, data
integrity, wire correctness, or a contract that cannot be supported safely; it
must be called out prominently in the changelog and migration notes. Error
identity, write-delivery classification, retry behavior, credential-generation
semantics, and counter definitions must never change silently.

The first `v0.1.0-rc.N` freezes the exported API and documented behavioral
contract. After that point, only compatible defect, documentation, test, and
security fixes are accepted. A necessary incompatible change returns the line
to beta instead of being hidden in a later RC.

The final `v0.1.0` release promises compatibility for the documented exported
surface throughout the `v0.1.x` line. It does not imply compatibility with every
directory product, server policy, operating system, or upstream go-ldap
release.

## Request ownership contract

Operations are synchronous and do not retain a request after the method
returns. The package copies each request's outer value and the mutable slices it
uses. Paging and DirSync controls are copied deeply because go-ldap mutates
them. Other custom `ldap.Control` implementations remain referenced through
their interface value and cannot be cloned generically.

Callers must therefore treat a request and every object reachable from its
custom controls as immutable until the operation returns. Reusing a custom
control concurrently is safe only when its implementation supports concurrent
`Encode` calls. The pool never assumes ownership of caller requests and never
mutates the caller's paging or DirSync cookie.

## RC entry gate

An RC requires all beta gates plus:

- a public validation record listing the tested AD DS build, topology relevant
  to connection routing, transport and authentication modes, and operation
  cases, without secrets or real directory contents;
- no unresolved release-blocking correctness, security, data-integrity, race,
  deadlock, or unbounded-resource issue;
- an explicit exported-API and documented-error diff against the preceding
  beta, with every intentional difference in the changelog;
- a review of dependency updates, residual vulnerability findings, shutdown
  and credential-rotation behavior, and observer redaction; and
- a successful signed-tag release-gate run from the exact candidate commit.

## Final v0.1.0 gate

The final release requires at least one RC, no contract change since the latest
RC, a fresh pass of the beta and RC gates on the release commit, complete
release notes, and public Go proxy and checksum-database verification. The
maintainer must also state explicitly whether the resulting v0.1.0 is
recommended for production use and which deployment constraints apply.
