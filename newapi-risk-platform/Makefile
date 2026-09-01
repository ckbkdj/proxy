.PHONY: fmt test race vet build run docker-up docker-down

fmt:
	gofmt -w ./cmd ./internal

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -trimpath -o bin/riskd ./cmd/riskd

run:
	go run ./cmd/riskd

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down
