.PHONY: run build test lint proto-lint proto-gen proto-format clean

GO ?= go
BINARY ?= backend-go

run:
	$(GO) run ./cmd/server

build:
	$(GO) build -o bin/$(BINARY) ./cmd/server

test:
	$(GO) test -race -cover ./...

lint:
	golangci-lint run ./...

proto-lint:
	buf lint

proto-gen:
	buf generate

proto-format:
	buf format -w

clean:
	rm -rf bin/ coverage.out coverage.html
