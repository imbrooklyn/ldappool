package ldappool_test

import (
	"context"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/imbrooklyn/ldappool"
)

func ExamplePool_WithConnection() {
	pool, err := ldappool.New(ldappool.Config{
		Endpoint: "ldaps://ldap.example.com",
		Auth: ldappool.AuthConfig{
			Mode:          ldappool.AuthSimple,
			BindPrincipal: "cn=service,dc=example,dc=com",
			Password:      ldappool.NewSecret([]byte("load-from-a-secret-store")),
		},
	})
	if err != nil {
		return
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = pool.Close(ctx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		100,
		5,
		false,
		"(objectClass=person)",
		[]string{"dn"},
		nil,
	)
	_ = pool.WithConnection(ctx, func(connection *ldappool.Connection) error {
		_, searchErr := connection.Search(ctx, request)
		return searchErr
	})
}
