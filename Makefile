# Loads .env if present, otherwise .env.example, so every target works from a
# fresh clone.
ENV_FILE := $(if $(wildcard .env),.env,.env.example)
WITH_ENV := set -a && . ./$(ENV_FILE) && set +a &&

.PHONY: build test test-unit test-db rls-smoke db-up db-down db-reset demo server ci

build:
	go build ./...
	go vet ./...

## Unit tests only (auth); database tests skip without the env.
test-unit:
	go test ./...

## Everything against the docker compose Postgres: Go integration tests
## (REQUIRE_DB=1 so nothing skips) and the SQL RLS smoke suite.
test-db: db-up
	$(WITH_ENV) REQUIRE_DB=1 go test -count=1 ./...
	$(MAKE) rls-smoke

rls-smoke: db-up
	$(WITH_ENV) psql "$$OWNER_DATABASE_URL" --no-psqlrc --quiet --set=ON_ERROR_STOP=1 -f sql/tests/rls_smoke.sql

test: test-db

db-up:
	docker compose up -d --wait

db-down:
	docker compose down -v

db-reset: db-down db-up

demo: db-up
	$(WITH_ENV) ./scripts/demo.sh

server: db-up
	$(WITH_ENV) go run ./cmd/seed && $(WITH_ENV) go run ./cmd/server

ci: build test
