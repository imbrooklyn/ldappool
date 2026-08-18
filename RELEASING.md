# Releasing

Releases are prepared from a clean, reviewed branch by a maintainer. Never tag
or publish a release from an unreviewed working tree.

The version-stage requirements in [BETA.md](BETA.md) are normative for beta,
RC, and final v0.1.0 releases.

## Repository gates

Protect `main` with a repository branch ruleset that requires pull requests,
review approval, resolved conversations, an up-to-date branch, and the
`required` job from the `CI` workflow (rendered as `CI / required`). Disable
force pushes and deletion, and do not permit administrators to bypass a failed
required check for a release commit.

The `Release Gate` workflow reruns the complete reusable CI workflow for a
version tag and independently verifies tag syntax, annotated-tag type, GitHub
signature verification, membership in `main`, and synchronized changelog and
version references. Its final check is `Release Gate / release-ready`.

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
   GOTOOLCHAIN=go1.26.6 go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
   ```

6. Run all five fuzz targets, benchmarks, API-surface checks,
   dependency-boundary checks, Linux amd64/arm64 and Windows amd64 cross-builds,
   and contention profiles. Investigate every regression.
7. Verify that public source and documentation are English and contain no
   secrets or real directory data.
8. Generate an SBOM and checksums for any additional binary or source archive
   artifacts. GitHub's automatically generated source archives are not
   maintainer-built release assets and must not be represented as such.
9. Merge the reviewed commit to protected `main` and wait for `CI / required`
   to succeed on that exact commit.
10. Create and push an annotated, signed SemVer tag from that commit. Use
    `vMAJOR.MINOR.PATCH-beta.N`, `vMAJOR.MINOR.PATCH-rc.N`, or
    `vMAJOR.MINOR.PATCH` as appropriate.
11. Wait for `Release Gate / release-ready` on the tag. Do not create or publish
    the GitHub Release while it is pending or failing.
12. Publish release notes from the changelog, attach the SBOM and checksums for
    every maintainer-built artifact, and verify the module through the public
    Go proxy and checksum database.

An infrastructure-only failure may be rerun after its cause is recorded. A
product, test, coverage, race, fuzz, cross-build, vulnerability, provenance, or
documentation failure requires a new reviewed commit and tag; do not move or
replace a published tag.

For v1.0.0, additionally freeze the documented error relationships, exported
API, counter semantics, state machine, and minimum compatibility promises.
