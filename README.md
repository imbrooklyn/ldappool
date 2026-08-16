# ldappool

`ldappool` is a concurrency-safe pool of reusable, authenticated LDAP
connections for Go. One pool represents exactly one endpoint, transport
security policy, and fixed authentication identity.

The API deliberately prevents callers from rebinding, changing TLS state,
closing a shared connection, or retaining the underlying `ldap.Client`.

> Status: alpha/experimental. The API is under validation until v1.0.0, and
> prereleases are not recommended for production use.

## Requirements

- Go 1.25 language compatibility or later; use a currently supported,
  security-patched toolchain. This release is validated with Go 1.25.13 and
  Go 1.26.6.
- `github.com/go-ldap/ldap/v3` v3.4.14
- LDAP, LDAPS, or LDAP with StartTLS

## Install

```sh
go get github.com/imbrooklyn/ldappool@v0.1.0-alpha.1
```

Pin an exact tag you have reviewed, and do not rely on `@latest` while the
module is experimental. Prereleases are not a production recommendation.

## Why this package

- Lazy connection creation: a temporarily unavailable directory does not
  prevent application startup.
- Fixed authenticated identity per pool, with safe credential rotation.
- FIFO acquisition, bounded waiters, cancellation, and direct connection
  handoff without broadcast wakeups.
- Idle and lifetime eviction with exact `MaxOpen` accounting, including
  connections whose physical close is still running.
- Pool-owned connection establishment, bounded exponential backoff, and a
  per-pool, in-process credential guard.
- Callback-scoped leases that become invalid after return and reject concurrent
  operations.
- Explicit write outcome semantics: an update that may have reached the server
  returns `ErrOutcomeUnknown` and is never retried automatically.
- Verified TLS by default, redacted errors and events, passive snapshots, and a
  framework-neutral observer.

## Basic use

```go
roots, err := x509.SystemCertPool()
if err != nil {
    return err
}

pool, err := ldappool.New(ldappool.Config{
    Endpoint: "ldaps://ldap.example.com:636",
    TLS: ldappool.TLSConfig{
        Mode:       ldappool.TLSImplicit,
        ServerName: "ldap.example.com",
        RootCAs:    roots,
    },
    Auth: ldappool.AuthConfig{
        Mode:          ldappool.AuthSimple,
        BindPrincipal: "cn=service,ou=applications,dc=example,dc=com",
        Password:      ldappool.NewSecret(passwordBytes),
    },
})
if err != nil {
    return err // static configuration error only; no network access occurred
}
defer func() {
    closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    _ = pool.Close(closeCtx)
}()

request := ldap.NewSearchRequest(
    "dc=example,dc=com",
    ldap.ScopeWholeSubtree,
    ldap.NeverDerefAliases,
    100,
    10,
    false,
    "(uid=alice)",
    []string{"dn", "displayName"},
    nil,
)

var result *ldap.SearchResult
err = pool.WithConnection(ctx, func(conn *ldappool.Connection) error {
    var searchErr error
    result, searchErr = conn.Search(ctx, request)
    return searchErr
})
```

The `Connection` value is valid only while its callback is running. Saving it
and using it later returns `ErrLeaseInvalid`; copying the value cannot extend
the lease because every copy shares the same invalidation state. Starting two
operations on the same lease concurrently returns `ErrConcurrentUse`.

## Configuration defaults

All invalid static combinations fail in `New` before any network activity.
Changing a configuration value after `New` does not reconfigure a pool; create
a new pool, except that the simple-Bind password may be changed with
`RotateCredentials`.

| Field | Zero/default behavior | Main constraints |
|---|---|---|
| `Endpoint` | No default | Required `ldap://` or `ldaps://` URL with only host and optional port |
| `TLS.Mode` | `TLSAuto` | LDAPS uses implicit TLS; LDAP uses StartTLS; plaintext is explicit |
| `TLS.ServerName` | Endpoint host | ASCII DNS A-label or IP address, without a port |
| `TLS.RootCAs` | System roots | A non-nil pool replaces system roots and is copied |
| `TLS.ClientCertificates` | None | Every entry needs a parseable chain and private key |
| `TLS.MinVersion` | TLS 1.2 | TLS 1.2 or TLS 1.3 only |
| `Auth.Mode` | Invalid | Explicit `AuthSimple` or `AuthAnonymous` |
| `Auth` identity | None | Simple mode requires principal and nonempty `Secret`; anonymous forbids both |
| `MaxOpen` / `MaxIdle` | 8 / `min(2, MaxOpen)` | `MaxOpen >= 1`; `1 <= MaxIdle <= MaxOpen` |
| `MaxWaiters` | 1024 | At least 1; bounds external FIFO waiters |
| `MaxIdleTime` / `MaxLifetime` | 5m / 30m | Positive and independent; the earlier expiry retires an idle connection |
| `ConnectTimeout` / `RequestTimeout` / `CloseTimeout` | 10s / 30s / 10s | Positive; each is a separate lifecycle budget |
| `ConnectBackoff` | 100ms, 2x, 30s cap, 20% jitter | Positive initial; multiplier >= 1; cap >= initial; jitter in `[0,1)` |
| `CredentialBackoff` | 5s, 2x, 5m cap, 30% jitter | Same validation; zero subfields select their documented defaults |
| `Dialer` | `net.Dialer` | Must honor context and return a fresh transport on every call |
| `CredentialFailureClassifier` | Conservative built-in policy | Trusted, synchronous, and must not retain raw diagnostics |
| `Observer` / `ObserverBuffer` | Disabled / 256 when enabled | Buffer is 1 through 65536; a nonzero buffer requires an observer |

Negative sizes or durations are invalid; zero selects the defaults above. The
ordinary and credential backoff maxima cannot be smaller than their initial
delays. `MaxIdleTime` and `MaxLifetime` have no required ordering.

## Security defaults

`TLSAuto` selects implicit TLS for `ldaps://` and StartTLS for `ldap://`. Both
verify the server certificate and reference identity before a simple Bind is
sent. TLS 1.2 is the default minimum. `InsecureSkipVerify` is intentionally not
exposed.

`Secret`, `Config`, `TLSConfig`, `AuthConfig`, `Pool`, `Connection`, and the
sensitive classifier input use constant redacted `String` and `GoString`
representations. Pool and lease internals are additionally stored behind opaque
state pointers, so explicitly copied handle values cannot be recursively
formatted into secrets or fork lifecycle state. Do not serialize configuration
values: they necessarily hold the endpoint, Bind principal, trust material,
optional client key, and secret needed to establish connections.
Certificate DER and slices are copied, but an arbitrary client private-key
signer cannot be cloned; it is a trusted shared object and must not be mutated
after `New`.

Plaintext simple Bind requires both `TLSPlaintext` and
`AllowInsecurePlaintextCredentials`; this explicit development-only mode must
not be used on an untrusted network. Anonymous authentication must also be
selected explicitly.

A pool never supports a second Bind. End-user password authentication must use
a separate, short-lived connection that is always closed and never enters this
pool.

## Operations

The v0.1 surface contains only synchronous operations that complete inside a
lease:

- `Search`, `SearchWithPaging`, `DirSync`, and `Compare`
- `Add`, `Modify`, `Del`, `ModifyDN`, and `PasswordModify`

Asynchronous searches, streaming responses, Bind, StartTLS, Unbind, arbitrary
Extended operations, `WhoAmI`, `ModifyWithResult`, and the raw LDAP client are
not exposed. `ModifyWithResult` and generic Extended operations remain excluded
because the selected upstream version does not strictly reject every unexpected
response shape.

## Context and operation outcomes

Acquisition observes the caller context. Connection establishment uses a
separate pool-owned context, so cancellation of the request that happened to
trigger a cold connection does not cancel recovery for every other caller.

Every operation combines its context with `RequestTimeout`. A cancellation or
timeout that races an active synchronous request closes that physical
connection. This is required because go-ldap's synchronous methods do not all
accept a context and an old response must never be observed by the next lease.

No operation is retried automatically. For writes:

- `errors.Is(err, ldappool.ErrNotSent)` means no request byte was written.
- `errors.As(err, *ldappool.OperationError)` and `ResultCode()` identify a
  complete server LDAP result.
- `errors.Is(err, ldappool.ErrOutcomeUnknown)` means the request may have taken
  effect, but the response could not be confirmed. Reconcile state or apply an
  application-specific idempotency strategy before retrying.

An operation whose success has already been confirmed remains successful even
if its context is canceled immediately afterward.

## Startup, backoff, and credentials

`New` validates and copies configuration but performs no DNS lookup, dial, TLS
handshake, or Bind. The first waiter starts connection creation. `Warmup` is
optional and does not poison or close the pool when it fails.

Ordinary connection backoff limits only new dials. It never prevents reuse of
an already healthy connection. If a healthy connection is borrowed, a waiter
remains queued for its return even while creation is delayed.

The credential guard is owned by one `Pool` and is not coordinated with other
pools in the same process. The conservative default treats Busy and Unavailable
as ordinary connection failures; it blocks future Bind attempts for
invalid credentials, unsupported or inappropriate authentication,
security-policy failures, and unknown complete Bind results. A custom
`CredentialFailureClassifier` can implement vendor policy. Its raw diagnostic
input is sensitive and must never be logged or retained. Vendor-specific
classifiers belong in separate optional modules.

A classifier is a trusted extension and must return promptly; it must not wait
on the same pool attempt that invoked it.

Use `RotateCredentials` to replace the password for the same Bind principal.
Existing connections from the old generation are retired; borrowed connections
are closed on return. Use `ResetCredentialGuard` only after an operator has
established that another probe is safe.

## Observability

`Snapshot` is passive: it takes no connection and performs no network health
check. Counter fields are mutually consistent at one pool-lock instant;
credential fields are sampled separately and may straddle a concurrent guard
transition.

An optional `Observer` receives redacted events from a bounded asynchronous
queue. Pool paths never wait for the observer. Full queues increment
`Snapshot.ObserverDropped`; observer panics are recovered. Events and snapshots
never include passwords, principals, DNs, filters, attribute values, or raw
server diagnostics. Do not put such values into metric labels in an adapter.

## Shutdown

`Close(ctx)` rejects new acquisition, wakes waiters, allows an LDAP operation
already in flight to finish within the shutdown budget, and then force-closes
remaining transports. A borrowed lease between operations is invalidated
immediately. `ForceClose(ctx)` starts with forced transport closure. Both are
idempotent and share the same terminal state.

Physical connections remain counted as open until their transport `Close`
returns or panics. A contract-violating custom transport whose `Close` blocks
forever can therefore make shutdown return `ErrCloseFailed`; it cannot cause the
pool to exceed `MaxOpen`.

## Compatibility and support

The module follows semantic versioning. During v0.x, incompatible corrections
may still be necessary. From v1.0.0, documented exported behavior will remain
compatible within v1. Dependency upgrades are reviewed against upstream source
and wire-conformance tests; new upstream methods never become public
automatically.

See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and
[CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
