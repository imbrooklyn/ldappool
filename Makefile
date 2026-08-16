.PHONY: all fmt vet test race repeat cover bench verify

all: fmt vet test race

fmt:
	@test -z "$$(gofmt -l .)"

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

repeat:
	go test -count=20 ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

bench:
	go test -run='^$$' -bench=. -benchmem ./...

verify:
	go mod verify
