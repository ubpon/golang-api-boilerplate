SHELL := /bin/bash
.DEFAULT_GOAL := help

MODULE        := github.com/ubpon/golang-api-boilerplate
BINARY        := bin/api
MIGRATIONS    := migrations
DATABASE_URL  ?= postgres://boilerplate:boilerplate@localhost:5432/boilerplate?sslmode=disable
MIGRATE_IMAGE := migrate/migrate:v4.18.1
GO_FILES      := $(shell find . -type f -name '*.go' -not -path './vendor/*')

ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: help
help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: run
run: ## Run the API from source
	go run ./cmd/api

.PHONY: build
build: ## Build a static binary into bin/api
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/api

.PHONY: fmt
fmt: ## Format all Go files
	gofmt -w $(GO_FILES)

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: test
test: ## Run unit and handler tests with the race detector
	go test -race -short ./...

.PHONY: test-integration
test-integration: ## Run every test, including testcontainers-backed integration tests
	go test -race -count=1 ./...

.PHONY: cover
cover: ## Produce a coverage profile and print the summary
	go test -race -short -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: sec
sec: ## Run gosec and govulncheck
	go run github.com/securego/gosec/v2/cmd/gosec@latest -exclude-generated -quiet ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: tidy
tidy: ## Tidy go.mod / go.sum
	go mod tidy

.PHONY: migrate-up
migrate-up: ## Apply all pending migrations
	docker run --rm --network host -v $(PWD)/$(MIGRATIONS):/migrations $(MIGRATE_IMAGE) \
		-path=/migrations -database "$(DATABASE_URL)" up

.PHONY: migrate-down
migrate-down: ## Roll back the most recent migration
	docker run --rm --network host -v $(PWD)/$(MIGRATIONS):/migrations $(MIGRATE_IMAGE) \
		-path=/migrations -database "$(DATABASE_URL)" down 1

.PHONY: migrate-create
migrate-create: ## Create a new migration pair: make migrate-create name=add_widgets
	@test -n "$(name)" || (echo "usage: make migrate-create name=add_widgets" && exit 1)
	docker run --rm -v $(PWD)/$(MIGRATIONS):/migrations $(MIGRATE_IMAGE) \
		create -ext sql -dir /migrations -seq -digits 4 $(name)

.PHONY: docker-up
docker-up: ## Start postgres, redis and mailhog
	docker compose up -d

.PHONY: docker-down
docker-down: ## Stop the local dependency stack and remove volumes
	docker compose down -v

.PHONY: docker-build
docker-build: ## Build the production container image
	docker build -t golang-api-boilerplate:local .

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf bin coverage.out
