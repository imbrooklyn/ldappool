# Contributing

Thank you for improving `ldappool`.

## Development requirements

- Go 1.25 language compatibility or later; use Go 1.25.13, Go 1.26.6, or a
  newer supported security-patched toolchain
- no real LDAP or Active Directory dependency in tests
- no network, database, web framework, worker, or business-repository
  dependency in the production package

Run the local checks before proposing a change:

```sh
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go test -count=20 ./...
go test -coverprofile=coverage.out ./...
```

Use channels and barriers for deterministic concurrent tests. Do not use
random sleeps as synchronization. Every wait must have an explicit timeout.
Each scripted dial must return a new independent transport; sharing one fake
client between dials hides lifecycle defects.

## Design constraints

Changes must preserve these boundaries:

- one pool has one endpoint, TLS policy, and fixed authentication identity;
- callers never receive `ldap.Client`, Bind, StartTLS, SetTimeout, or Close;
- one lease runs at most one operation at a time and expires after its callback;
- closing connections count toward `MaxOpen` until physical close completes;
- write operations are never retried automatically;
- a dispatched write with an unconfirmed result reports `ErrOutcomeUnknown`;
- observer and classifier callbacks never execute under pool or guard locks;
- public errors, events, snapshots, tests, and examples contain no secrets or
  directory input.

New production abstractions must have a genuine deployment use, not exist only
to make a test easier. Public API additions require an operation-matrix review,
API reflection test updates, documentation, and a compatibility assessment.

## Tests and dependencies

Use `net.Pipe`, in-memory certificates, and scripted BER peers. Include the
race detector for changes to lifecycle, waiter, guard, observer, or transport
code. Add fuzz seeds for malformed protocol input and property assertions for
counter transitions where relevant.

The preferred direct production dependency set is the Go standard library plus
`github.com/go-ldap/ldap/v3`. Do not add a framework, logger, metrics SDK, test
assertion framework, or business package without a compelling public-library
need.

## Documentation and commits

Exported Go identifiers require English GoDoc. Public repository documents and
comments are English.

Keep changes focused. Do not commit generated coverage, profile, binary, or
module-cache artifacts.
