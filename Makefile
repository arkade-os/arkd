.PHONY: \
	build build-all build-cli build-wallet clean cov \
	docker-run docker-run-light docker-stop droppg droppgtest \
	help integrationtest lint migrate pg pgmigrate pgsqlc pgtest \
	pprof proto proto-lint psql \
	redis-down redis-test-down redis-test-up redis-up \
	run run-light run-signer run-simulation run-wallet run-wallet-nosigner \
	sqlc test test-pkg vet

define setup_env
    $(eval include $(1))
    $(eval export)
endef

GOLANGCI_LINT ?= $(shell \
	echo "docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v2.9.0 golangci-lint"; \
)

## buf: create local dockerized buf
buf:
	@if ! docker image inspect buf >/dev/null 2>&1; then \
		docker build -q -t buf -f buf.Dockerfile . &> /dev/null; \
	fi

## build: build arkd for your platform
build:
	@echo "Building arkd binary..."
	@bash ./scripts/build-arkd

## build-all: build arkd binary for all platforms
build-all:
	@echo "Building arkd binary for all platforms..."
	@bash ./scripts/build-all

## build-cli: build ark cli for your platforms
build-cli:
	@echo "Building ark cli binary..."
	@bash ./pkg/ark-cli/scripts/build

## build-wallet: build arkd wallet for your platforms
build-wallet:
	@echo "Building arkd wallet binary..."
	@bash ./scripts/build-arkd-wallet

## clean: run go clean
clean:
	@echo "Cleaning..."
	@go clean

## cov: generate coverage report
cov:
	@echo "Coverage..."
	@go test -cover ./internal/...
	@find ./pkg -name go.mod -execdir go test -cover ./... \;

## docker-run: start docker test environment with postgres
docker-run:
	@echo "Running dockerized arkd and arkd wallet in test mode on regtest with postgres..."
	@set -a && . envs/arkd.dev.docker.env && set +a && \
		docker compose -f docker-compose.regtest.yml up --build -d

## docker-run-light: start docker test environment with sqlite/badger/inmemory
docker-run-light:
	@echo "Running dockerized arkd and arkd wallet in test mode on regtest (light mode)..."
	@docker compose -f docker-compose.regtest.yml up --build -d

## docker-stop: tear down docker test environment
docker-stop:
	@echo "Stopping dockerized arkd and arkd wallet in test mode on regtest..."
	@docker compose -f docker-compose.regtest.yml down -v

## droppg: stop and remove postgres container
droppg:
	@echo "Stopping postgres db..."
	@docker stop ark-pg > /dev/null 2>&1
	@docker rm ark-pg > /dev/null 2>&1

## droppgtest: stop and remove postgres container
droppgtest:
	@echo "Stopping postgres test db..."
	@docker stop ark-pg-test > /dev/null 2>&1 || true
	@docker rm ark-pg-test > /dev/null 2>&1 || true

## help: print this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## integrationtest: run integration tests
integrationtest:
	@echo "Running integration tests..."
	@go test -v -count 1 -timeout 1200s github.com/arkade-os/arkd/internal/test/e2e

## lint: lint codebase
lint:
	@echo "Linting code..."
	@$(GOLANGCI_LINT) run --fix --tests=false

## migrate: create sqlite migration file(eg. make FILE=init mig_file)
migrate:
	@docker run --rm -v ./internal/infrastructure/db/sqlite/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

## pg: start postgres db inside docker container
pg:
	@echo "Starting postgres db..."
	@docker compose -f docker-compose.regtest.yml up -d pg

## pgmigrate: create pg migration file (e.g. make FILE=init pgmigrate)
pgmigrate:
	@docker run --rm -v ./internal/infrastructure/db/postgres/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

## pgsqlc: compile sql queries for postgres
pgsqlc:
	@docker run --rm -v ./internal/infrastructure/db/postgres:/src -w /src sqlc/sqlc:1.30.0 generate

## pgtest: start postgres db inside docker container
pgtest:
	@echo "Starting postgres test db..."
	@docker run --name ark-pg-test -v ./scripts:/docker-entrypoint-initdb.d:ro -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=event -d postgres > /dev/null 2>&1 

## pprof: run pprof tool (e.g. make pprof PROFILE=heap)
pprof:
	@echo "Running pprof..."
	@go tool pprof -http=:8080 http://localhost:7071/debug/pprof/$(PROFILE)

## proto: generate proto stubs
proto: proto-lint
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

## proto-lint: lint protos
proto-lint: buf
	@echo "Linting protos..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint

## psql: connect to postgres terminal running inside docker container
psql:
	@docker exec -it ark-pg psql -U root -d event -c "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema');" \
	&& docker exec -it ark-pg psql -U root -d projection

## redis-down: stop and remove redis container started via compose
redis-down:
	@echo "Stopping redis from docker compose..."
	@docker compose -f docker-compose.regtest.yml stop redis > /dev/null 2>&1 || true
	@docker compose -f docker-compose.regtest.yml rm -f redis > /dev/null 2>&1 || true

## redis-test-down: stop and remove unit test redis container
redis-test-down:
	@echo "Stopping redis for unit tests..."
	@docker stop ark-redis-test > /dev/null 2>&1 || true
	@docker rm ark-redis-test > /dev/null 2>&1 || true

## redis-test-up: start redis db for unit tests (no nigiri network required)
redis-test-up:
	@echo "Starting redis for unit tests..."
	@docker run -d --name ark-redis-test -p 6379:6379 redis:7-alpine > /dev/null 2>&1 || true

## redis-up: start redis db inside docker container (compose, requires nigiri network)
redis-up:
	@echo "Starting redis via docker compose (integration/dev)..."
	@docker compose -f docker-compose.regtest.yml up -d redis

## run: run arkd in regtest
run: clean pg redis-up
	@sleep 2
	@echo "Running arkd in dev mode on regtest"
	$(call setup_env, envs/arkd.dev.env)
	@go run ./cmd/arkd

## run-light: run arkd in light mode
run-light: clean
	@echo "Running arkd in light mode on regtest"
	$(call setup_env, envs/arkd.light.env)
	@go run ./cmd/arkd

## run-signer: run arkd wallet as signer without a wallet
run-signer:
	@echo "Running signer in dev mode"
	@docker compose -f docker-compose.regtest.yml up -d pg nbxplorer
	$(call setup_env, envs/signer.dev.env)
	@go run ./cmd/arkd-wallet

## run-simulation: run the multi-VTXO batch settlement test
## Usage: make run-simulation [CLIENTS=n] [MIN=n] [MAX=n]
# Examples:
#   make run-simulation                  # Default: 5 clients, min=5, max=128
#   make run-simulation CLIENTS=10       # 10 clients, min=10, max=128
#   make run-simulation CLIENTS=10 MAX=10  # 10 clients, exact batch size of 10
#   make run-simulation CLIENTS=20 MIN=5   # 20 clients, minimum batch size of 5
run-simulation:
	@echo "Stopping any existing Docker environment..."
	@docker compose -f docker-compose.regtest.yml down -v 2>/dev/null || true
	@echo "Starting Docker environment with batch configuration..."
	@bash -c '\
		CLIENTS="$${CLIENTS:-5}"; \
		MIN="$${MIN:-$$CLIENTS}"; \
		MAX="$${MAX:-128}"; \
		echo "Configuration: CLIENTS=$$CLIENTS, MIN=$$MIN, MAX=$$MAX"; \
		ARKD_ROUND_MIN_PARTICIPANTS_COUNT=$$MIN \
		ARKD_ROUND_MAX_PARTICIPANTS_COUNT=$$MAX \
		ARKD_SESSION_DURATION=60 \
		docker compose -f docker-compose.regtest.yml up --build -d; \
	'
	@echo "Waiting for services to start..."
	@sleep 30
	@bash -c '\
		CLIENTS="$${CLIENTS:-5}"; \
		MIN="$${MIN:-$$CLIENTS}"; \
		MAX="$${MAX:-128}"; \
		echo "Running batch settlement test with $$CLIENTS clients (MIN=$$MIN, MAX=$$MAX)..."; \
		go test -v -count=1 -timeout 1200s github.com/arkade-os/arkd/test/e2e -run TestBatchSettleMultipleClients -args -smoke -num-clients=$$CLIENTS; \
	'
	@echo "Test completed. Docker environment will remain running."
	@echo "Run 'make docker-stop' to shut down the environment when finished."

## run-wallet: run arkd wallet based on nbxplorer in dev mode on regtest with a pre-loaded signer private key
run-wallet:
	@echo "Running arkd wallet in dev mode with NBXplorer on regtest with pre-loaded signer private key..."
	@docker compose -f docker-compose.regtest.yml up -d pg nbxplorer
	$(call setup_env, envs/arkd-wallet.regtest.env)
	@go run ./cmd/arkd-wallet

## run-wallet-nosigner: run arkd wallet based on nbxplorer in dev mode on regtest without a pre-loaded signer private key
run-wallet-nosigner:
	@echo "Running arkd wallet in dev mode with NBXplorer on regtest..."
	@docker compose -f docker-compose.regtest.yml up -d pg nbxplorer
	$(call setup_env, envs/arkd-wallet-nosigner.regtest.env)
	@go run ./cmd/arkd-wallet

## sqlc: compile sql queries for sqlite
sqlc:
	@echo "gen sql..."
	@docker run --rm -v ./internal/infrastructure/db/sqlite:/src -w /src sqlc/sqlc:1.30.0 generate

## test: run unit tests
test: pgtest redis-test-up
	@sleep 2
	@echo "Running unit tests..."
	@failed=0; \
	go test -v -count=1 -race $(shell go list ./internal/... | grep -v '/internal/test') || failed=1; \
	$(MAKE) droppgtest; $(MAKE) redis-test-down; \
	exit $$failed

## test-pkg: run unit tests for all packages in pkg/
test-pkg:
	@find ./pkg -name go.mod -execdir go test -v ./... \;

## vet: run code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...