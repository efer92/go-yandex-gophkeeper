MODULE     := github.com/efremov/gophkeeper
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS    := -ldflags "-X $(MODULE)/internal/shared/version.Version=$(VERSION) \
                         -X $(MODULE)/internal/shared/version.BuildDate=$(BUILD_DATE)"

.PHONY: all proto swagger server client \
        client-linux-amd64 client-linux-arm64 \
        client-darwin-amd64 client-darwin-arm64 \
        client-windows-amd64 client-all \
        test test-integration lint migrate migrate-down \
        docker-up docker-down tls-dev clean

all: server client

proto:
	buf generate

swagger:
	buf generate
	@echo "OpenAPI spec generated at gen/openapi/gophkeeper.swagger.json"

server:
	go build $(LDFLAGS) -o bin/server ./cmd/server

client:
	go build $(LDFLAGS) -o bin/gophkeeper ./cmd/client
	@codesign -s - bin/gophkeeper 2>/dev/null || true
	cp bin/gophkeeper gophkeeper

client-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/gophkeeper-linux-amd64 ./cmd/client

client-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/gophkeeper-linux-arm64 ./cmd/client

client-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/gophkeeper-darwin-amd64 ./cmd/client

client-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/gophkeeper-darwin-arm64 ./cmd/client
	@codesign -s - bin/gophkeeper-darwin-arm64 2>/dev/null || true

client-windows-amd64:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/gophkeeper-windows-amd64.exe ./cmd/client

# Build all client platforms at once
client-all: client-linux-amd64 client-linux-arm64 client-darwin-amd64 client-darwin-arm64 client-windows-amd64

TESTPKGS := $(shell go list ./... | grep -vE '/(gen|cmd|testutil|storage/postgres|client/tui)(/|$$)')

test:
	go test $(TESTPKGS) -race -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out | grep total

test-integration:
	go test -tags=integration -race -count=1 ./tests/integration/...

lint:
	golangci-lint run ./...

migrate:
	goose -dir internal/server/storage/migrations postgres "$(DATABASE_URL)" up

migrate-down:
	goose -dir internal/server/storage/migrations postgres "$(DATABASE_URL)" down

docker-up:
	docker compose up -d
	@echo "Waiting for postgres..." && sleep 3

docker-down:
	docker compose down

tls-dev:
	mkdir -p testdata/certs
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
	  -keyout testdata/certs/server.key \
	  -out testdata/certs/server.crt \
	  -subj "/CN=localhost" \
	  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

clean:
	rm -rf bin/ coverage.out
