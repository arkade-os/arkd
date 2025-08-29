.PHONY: build build-all clean cov docker-run docker-stop droppg droppgtest help integrationtest lint migrate pg pgsqlc pgtest pgmigrate psql proto proto-lint run run-light run-wallet-bitcoind run-wallet-neutrino sqlc test vet

define setup_env
    $(eval include $(1))
    $(eval export)
endef

## build: build arkd for your platforms
build:
	@echo "Building arkd binary..."
	@bash ./scripts/build-arkd

## build-cli: build ark cli for your platforms
build-cli:
	@echo "Building ark cli binary..."
	@bash ./pkg/ark-cli/scripts/build

## build-wallet: build arkd wallet for your platforms
build-wallet:
	@echo "Building arkd wallet binary..."
	@bash ./scripts/build-arkd-wallet

# build-all: builds arkd binary for all platforms
build-all:
	@echo "Building arkd binary for all platforms..."
	@bash ./scripts/build-all

## clean: cleans the binary
clean:
	@echo "Cleaning..."
	@go clean

## cov: generates coverage report
cov:
	@echo "Coverage..."
	@go test -cover ./internal/...
	@find ./pkg -name go.mod -execdir go test -cover ./... \;

## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## intergrationtest: runs integration tests
integrationtest:
	@echo "Running integration tests..."
	@go test -v -count 1 -timeout 800s github.com/arkade-os/arkd/test/e2e

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix

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

## test: runs unit and component tests
test: pgtest redis-up
	@sleep 2
	@echo "Running unit tests..."
	-@go test -v -count=1 -race ./internal/...
	-@find ./pkg -name go.mod -execdir go test -v ./... \;
	@$(MAKE) droppgtest && $(MAKE) redis-down

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...

## migrate: creates sqlite migration file(eg. make FILE=init mig_file)
migrate:
	@docker run --rm -v ./internal/infrastructure/db/sqlite/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

## sqlc: gen sql
sqlc:
	@echo "gen sql..."
	@docker run --rm -v ./internal/infrastructure/db/sqlite:/src -w /src sqlc/sqlc generate

#### Postgres database ####
# pg: starts postgres db inside docker container
pg:
	@echo "Starting postgres db..."
	@docker run --name ark-pg -v ./scripts:/docker-entrypoint-initdb.d:ro -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=event -d postgres > /dev/null 2>&1 || true

# pgtest: starts postgres db inside docker container
pgtest:
	@echo "Starting postgres test db..."
	@docker run --name ark-pg-test -v ./scripts:/docker-entrypoint-initdb.d:ro -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=event -d postgres > /dev/null 2>&1 

# droppg: stop and remove postgres container
droppg:
	@echo "Stopping postgres db..."
	@docker stop ark-pg > /dev/null 2>&1
	@docker rm ark-pg > /dev/null 2>&1

# droppgtest: stop and remove postgres container
droppgtest:
	@echo "Stopping postgres test db..."
	@docker stop ark-pg-test > /dev/null 2>&1 || true
	@docker rm ark-pg-test > /dev/null 2>&1 || true

# psql: connects to postgres terminal running inside docker container
psql:
	@docker exec -it ark-pg psql -U root -d event -c "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema');" \
	&& docker exec -it ark-pg psql -U root -d projection

# pgmigrate: creates pg migration file (e.g. make FILE=init pgmigrate)
pgmigrate:
	@docker run --rm -v ./internal/infrastructure/db/postgres/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

# pgsqlc: generate sql code for postgres
pgsqlc:
	@docker run --rm -v ./internal/infrastructure/db/postgres:/src -w /src sqlc/sqlc generate

#### Redis database ####
# redis-up: starts redis db inside docker container
redis-up:
	@echo "Starting redis..."
	@docker run --name ark-redis -d -p 6379:6379 redis:7-alpine > /dev/null 2>&1 || true

# redis-down: stop and remove redis container
redis-down:
	@echo "Stopping redis..."
	@docker stop ark-redis > /dev/null 2>&1 || true
	@docker rm ark-redis > /dev/null 2>&1 || true

proto: proto-lint
	@echo "Compiling stubs..."
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf generate

# proto-lint: lints protos
proto-lint:
	@echo "Linting protos..."
	@docker build -q -t buf -f buf.Dockerfile . &> /dev/null
	@docker run --rm --volume "$(shell pwd):/workspace" --workdir /workspace buf lint

# docker-run: starts docker test environment
docker-run:
	@echo "Running dockerized arkd and arkd wallet in test mode on regtest..."
	@docker compose -f docker-compose.regtest.yml up --build -d

# docker-stop: tears down docker test environment
docker-stop:
	@echo "Stopping dockerized arkd and arkd wallet in test mode on regtest..."
	@docker compose -f docker-compose.regtest.yml down -v

## run-wallet-bitcoind: run arkd wallet in dev mode with bitcoind on regtest
run-wallet-bitcoind:
	@echo "Running arkd wallet in dev mode with Bitcoin Core on regtest..."
	$(call setup_env, envs/arkd-wallet.bitcoind.regtest.env)
	@go run ./cmd/arkd-wallet

## run-wallet-neutrino: run arkd wallet in dev mode with neutrino on regtest
run-wallet-neutrino:
	@echo "Running arkd wallet in dev mode with Neutrino on regtest..."
	$(call setup_env, envs/arkd-wallet.neutrino.regtest.env)
	@go run ./cmd/arkd-wallet