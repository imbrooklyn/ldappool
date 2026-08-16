package ldappool

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestPublicPoolMethodSurface(t *testing.T) {
	typeOf := reflect.TypeOf((*Pool)(nil))
	got := make([]string, 0, typeOf.NumMethod())
	for i := 0; i < typeOf.NumMethod(); i++ {
		got = append(got, typeOf.Method(i).Name)
	}
	want := []string{"Close", "ForceClose", "GoString", "ResetCredentialGuard", "RotateCredentials", "Snapshot", "String", "Warmup", "WithConnection"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Pool methods = %v, want %v", got, want)
	}
}

func TestSecuritySensitiveConfigurationSurface(t *testing.T) {
	tlsType := reflect.TypeOf(TLSConfig{})
	for _, forbidden := range []string{"InsecureSkipVerify", "VerifyPeerCertificate", "VerifyConnection"} {
		if _, ok := tlsType.FieldByName(forbidden); ok {
			t.Fatalf("TLSConfig exposes unsafe field %s", forbidden)
		}
	}
	connectionType := reflect.TypeOf((*Connection)(nil))
	for _, forbidden := range []string{"Bind", "SimpleBind", "UnauthenticatedBind", "StartTLS", "Close", "Client", "Raw", "SearchAsync", "DirSyncAsync", "Syncrepl", "Extended", "ModifyWithResult"} {
		if _, ok := connectionType.MethodByName(forbidden); ok {
			t.Fatalf("Connection exposes forbidden method %s", forbidden)
		}
	}
}

func TestProductionImportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	var forbidden []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(files, filepath.Clean(name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(path, ".") || path == "github.com/go-ldap/ldap/v3" || path == "github.com/go-asn1-ber/asn1-ber" {
				continue
			}
			forbidden = append(forbidden, name+":"+path)
		}
	}
	sort.Strings(forbidden)
	if len(forbidden) != 0 {
		t.Fatalf("production dependency boundary violated: %v", forbidden)
	}
}

func TestExportedTypesDoNotEmbedLDAPClient(t *testing.T) {
	client := reflect.TypeOf((*ldap.Client)(nil)).Elem()
	for _, value := range []any{Config{}, TLSConfig{}, AuthConfig{}, Snapshot{}, Event{}, Connection{}, Pool{}} {
		typeOf := reflect.TypeOf(value)
		for i := 0; i < typeOf.NumField(); i++ {
			field := typeOf.Field(i)
			if field.IsExported() && (field.Type == client || field.Type.Implements(client)) {
				t.Fatalf("%s exposes ldap.Client in field %s", typeOf, field.Name)
			}
		}
	}
}
