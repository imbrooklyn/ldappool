package ldappool

import "runtime"

const redactedSecret = "[REDACTED]"

// Secret contains sensitive authentication material.
//
// NewSecret copies its input. Pool construction and credential rotation copy a
// Secret again so the caller may discard its copy immediately. Go strings made
// by the LDAP dependency cannot be reliably erased from memory.
type Secret struct {
	data []byte
}

// NewSecret returns a Secret containing a copy of value.
func NewSecret(value []byte) Secret {
	return Secret{data: append([]byte(nil), value...)}
}

// String always returns a redaction marker.
func (Secret) String() string { return redactedSecret }

// GoString always returns a redaction marker.
func (Secret) GoString() string { return redactedSecret }

func (s Secret) cloneBytes() []byte {
	return append([]byte(nil), s.data...)
}

func (s Secret) empty() bool { return len(s.data) == 0 }

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
	runtime.KeepAlive(value)
}
