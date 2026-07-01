FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X github.com/efremov/gophkeeper/internal/shared/version.Version=docker \
              -X github.com/efremov/gophkeeper/internal/shared/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /bin/server ./cmd/server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/server /bin/server
EXPOSE 50051
ENTRYPOINT ["/bin/server"]
