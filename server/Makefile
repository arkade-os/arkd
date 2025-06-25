.PHONY: build clean cov help integrationtest lint run run-light test vet migrate sqlc pg pgtest droppg droppgtest psql pgmigrate pgsqlc

define setup_env
    $(eval include $(1))
    $(eval export)
endef

## build: build for all platforms
build:
	@echo "Building arkd binary..."
	@bash ./scripts/build

## clean: cleans the binary
clean:
	@echo "Cleaning..."
	@go clean

## cov: generates coverage report
cov:
	@echo "Coverage..."
	@go test -cover ./...

## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

## intergrationtest: runs integration tests
integrationtest:
	@echo "Running integration tests..."
	@go test -v -count 1 -timeout 500s github.com/ark-network/ark/server/test/e2e

## lint: lint codebase
lint:
	@echo "Linting code..."
	@golangci-lint run --fix

## run: run arkd in regtest
run: clean
	@echo "Running arkd in regtest"
	$(call setup_env, envs/dev.env)
	go run ./cmd/arkd

## run-light: run arkd in light mode
run-light: clean
	@echo "Running arkd in light mode"
	$(call setup_env, envs/light.env)
	go run ./cmd/arkd

## test: runs unit and component tests
test:
	@echo "Running unit tests..."
	@go test -v -count=1 -race ./internal/...
	@find ./pkg -name go.mod -execdir go test -v -count=1 -race ./... \;

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
	@docker run --name ark-pg -v ./scripts:/docker-entrypoint-initdb.d:ro -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=event -d postgres 

# pgtest: starts postgres db inside docker container
pgtest:
	@docker run --name ark-pg-test -v ./scripts:/docker-entrypoint-initdb.d:ro -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=event -d postgres 

# droppg: stop and remove postgres container
droppg:
	@docker stop ark-pg
	@docker rm ark-pg

# droppgtest: stop and remove postgres container
droppgtest:
	@docker stop ark-pg-test
	@docker rm ark-pg-test

# psql: connects to postgres terminal running inside docker container
psql:
	@docker exec -it ark-pg psql -U root -d event -c "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema');" \
	&& docker exec -it ark-pg psql -U root -d projection

# pgmigrate: creates pg migration file (e.g. make FILE=init pgmigrate)
pgmigrate:
	@docker run --rm -v ./internal/infrastructure/db/postgres/migration:/migration migrate/migrate create -ext sql -dir /migration $(FILE)

# pgsqlc: generate sql code for postgres
pgsqlc:
	@docker run --rm -v $(PWD)/internal/infrastructure/db/postgres:/src -w /src sqlc/sqlc generate


#### Redis database ####
# redis-up: starts redis db inside docker container
redis-up:
	@docker run --name ark-redis -d -p 6379:6379 redis:7-alpine

# redis-down: stop and remove redis container
redis-down:
	@docker stop ark-redis || true
	@docker rm ark-redis || true
