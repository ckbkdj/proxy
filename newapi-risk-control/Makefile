.PHONY: fmt test vet build run compose-up compose-down

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

test:
	go test -race ./...

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -trimpath -o bin/riskgate ./cmd/riskgate

run:
	go run ./cmd/riskgate

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down
