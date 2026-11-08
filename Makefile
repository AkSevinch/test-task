GO ?= go
OAPI_CODEGEN_VERSION ?= v2.8.2
LOCAL_DB_URL ?= postgres://threat:threat@localhost:5433/threats?sslmode=disable

.PHONY: help generate build run test test-integration fmt vet lint docker-build docker-up docker-down clean

help: ## Показать цели
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-18s %s\n", $$1, $$2}'

generate: ## Пересобрать код из api/openapi.yaml
	$(GO) run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) --config oapi-codegen.yaml api/openapi.yaml

build: ## Собрать все пакеты
	$(GO) build ./...

run: ## Запустить сервис, нужен PostgreSQL на localhost:5433
	$(GO) run ./cmd/server

test: ## Запустить юнит- и HTTP-тесты
	$(GO) test ./...

test-integration: ## Запустить интеграционные тесты с PostgreSQL
	docker compose up -d db
	@echo "ждём PostgreSQL"
	@until docker compose exec -T db pg_isready -U threat -d threats >/dev/null 2>&1; do sleep 1; done
	TEST_DATABASE_URL='$(LOCAL_DB_URL)' $(GO) test ./internal/store -run Integration -count=1 -v

fmt: ## Отформатировать Go-код
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

vet: ## Запустить go vet
	$(GO) vet ./...

lint: fmt vet ## Форматирование и vet

docker-build: ## Собрать Docker-образы
	docker compose build

docker-up: ## Поднять весь стек в Docker
	docker compose up -d --build

docker-down: ## Остановить стек
	docker compose down

clean: ## Удалить артефакты сборки
	rm -rf bin
