# Third-Party Notices

`ldappool` is licensed under the MIT License. Its compiled production-package
dependency graph at v0.1.0-alpha.2 includes the following third-party modules.
Upstream modules may declare additional dependencies for optional subpackages
and their own tests; those are not linked into this package. Each dependency's
own license file is authoritative and must be preserved when source is
redistributed.

| Module | Version | License | Use |
|---|---:|---|---|
| `github.com/go-ldap/ldap/v3` | v3.4.14 | MIT | Direct LDAP protocol dependency |
| `github.com/Azure/go-ntlmssp` | v0.1.1 | MIT | Transitive go-ldap dependency |
| `github.com/go-asn1-ber/asn1-ber` | v1.5.8 | MIT | Direct BER encoding and strict response validation dependency |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause | Transitive go-ldap dependency |
| `golang.org/x/crypto` | v0.54.0 | BSD-3-Clause | Transitive cryptography dependency |

The dependency versions above are recorded in `go.mod` and `go.sum`. This
notice is informational and does not replace any dependency's license text.

The 2026-08-18 release scan reports
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) at the
`golang.org/x/crypto` module level. The affected `openpgp` package is not
imported or reachable in the production package graph, and the advisory has no
fixed module version. The release therefore records it as an accepted,
unreachable dependency risk and continues to scan it on every update.
