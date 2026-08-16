# Releasing

Releases are prepared from a clean, reviewed branch by a maintainer. Never tag
or publish a release from an unreviewed working tree.

## Release checklist

1. Confirm the intended semantic version, supported Go lines, and the latest
   security-patched release on each line. Update the exact CI patch versions;
   do not rely on a floating `.x` selector for release validation.
2. Review the complete diff and public API surface.
3. Review upstream go-ldap changes and all transitive dependency licenses.
4. Update `CHANGELOG.md`, `THIRD_PARTY_NOTICES.md`, and version references.
5. Run:

   ```sh
   go mod tidy
   go mod verify
   go vet ./...
   go test ./...
   go test -race -count=10 ./...
   go test -count=20 ./...
   go test -coverprofile=coverage.out ./...
   GOTOOLCHAIN=go1.26.6 govulncheck ./...
   ```

6. Run all five fuzz targets, benchmarks, API-surface checks,
   dependency-boundary checks, Linux amd64/arm64 and Windows amd64 cross-builds,
   and contention profiles. Investigate every regression.
7. Verify that public source and documentation are English and contain no
   secrets or real directory data.
8. Generate an SBOM and checksums for any binary or source archive artifacts.
9. Create a signed `vMAJOR.MINOR.PATCH` tag from the reviewed commit.
10. Publish release notes from the changelog and verify the module through the
    public Go proxy and checksum database.

For v1.0.0, additionally freeze the documented error relationships, exported
API, counter semantics, state machine, and minimum compatibility promises.
