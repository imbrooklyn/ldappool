// Package ldappool provides a concurrency-safe pool of reusable, authenticated
// LDAP connections.
//
// A Pool has exactly one endpoint, transport-security policy, and authentication
// identity. Connections are exposed only through callback-scoped leases, so a
// caller cannot rebind, start TLS, close, or retain the underlying LDAP client.
// The package never retries LDAP operations automatically. In particular, a
// write that may have reached the server is reported with ErrOutcomeUnknown.
package ldappool
