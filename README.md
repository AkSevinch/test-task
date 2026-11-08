# Information Exchange Service

Небольшой REST-сервис для обмена информацией об угрозах
Написан на Go по спецификации [`api/openapi.yaml`](api/openapi.yaml)

## Что умеет

- создаёт запись об угрозе через `POST /info`
- отдаёт запись по MD5 через `GET /info/{md5}`
- полностью заменяет запись через `PUT /info/{md5}`
- хранит расширенную модель: тип и критичность угрозы, статус проверки, данные файла, теги, confidence, first_seen и last_seen, created_at и updated_at
- проверяет запрос дважды, сначала по OpenAPI, потом по правилам домена
- хранит данные в PostgreSQL, миграции накатываются при старте
- есть юнит-тесты, HTTP-тесты и интеграционный тест с базой
- собирается в Docker, в compose есть сервис и PostgreSQL

## Стек

| Компонент | Что используется |
|---|---|
| Язык | Go 1.26 |
| HTTP-роутер | chi v5 |
| Кодогенерация | oapi-codegen v2, chi-server, strict-server, models |
| СУБД | PostgreSQL 16 |
| Драйвер | pgx v5, pgxpool |
| Валидация | kin-openapi и oapi-codegen/nethttp-middleware |

## Модель угрозы

Обязательные поля только `md5` и `name`
Остальные можно не передавать, тогда подставятся значения по умолчанию

| Поле | Тип | Ограничения и значения по умолчанию |
|---|---|---|
| `md5` | string | 32 hex-символа, приводится к нижнему регистру |
| `name` | string | 1..200 символов, обрезается по краям |
| `threat_type` | enum | `trojan`, `virus`, `worm`, `ransomware`, `spyware`, `adware`, `rootkit`, `backdoor`, `miner`, `pua`, `other`, по умолчанию `other` |
| `severity` | enum | `low`, `medium`, `high`, `critical`, по умолчанию `medium` |
| `status` | enum | `active`, `inactive`, `false_positive`, `under_review`, по умолчанию `active` |
| `description` | string | до 4096 символов |
| `file_type` | string | до 255 символов |
| `file_size` | int64 | больше или равно 0 |
| `confidence` | int или null | 0..100 |
| `tags` | string[] | до 20 уникальных тегов, каждый 1..64 символа |
| `source` | string | до 64 символов, по умолчанию `manual` |
| `first_seen` | date-time или null | не позже `last_seen` |
| `last_seen` | date-time или null | |
| `created_at` | date-time | только в ответе, ставит сервер |
| `updated_at` | date-time | только в ответе, ставит сервер |

`PUT` работает как полная замена
Если поле не передали, оно сбрасывается к значению по умолчанию
`md5` берётся из пути и не меняется
`created_at` остаётся прежним

## Как запустить

Проще всего через Docker

```bash
docker compose up --build -d
curl http://localhost:8080/readyz
```

Сервис будет на `http://localhost:8080`
PostgreSQL проброшен на `localhost:5433`, чтобы не конфликтовать с локальной базой на 5432

Если Docker нужен только для базы

```bash
docker compose up -d db
make run
```

## Настройки

| Переменная | По умолчанию | Что делает |
|---|---|---|
| `PORT` | `8080` | Порт HTTP-сервера |
| `DATABASE_URL` | `postgres://threat:threat@localhost:5433/threats?sslmode=disable` | DSN PostgreSQL |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

## Примеры запросов

Создание

```bash
curl -s -X POST http://localhost:8080/info \
  -H 'Content-Type: application/json' \
  -d '{
    "md5": "D41D8CD98F00B204E9800998ECF8427E",
    "name": "Trojan.Win32.Generic",
    "threat_type": "trojan",
    "severity": "high",
    "description": "Крадёт учётные данные из браузеров",
    "file_type": "PE32 executable",
    "file_size": 124928,
    "confidence": 95,
    "tags": ["banker", "windows"],
    "source": "feed",
    "first_seen": "2026-01-15T10:30:00Z",
    "last_seen": "2026-02-01T08:00:00Z"
  }'
```

Получение

```bash
curl -s http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```

Обновление, тут PUT заменяет запись целиком

```bash
curl -s -X PUT http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e \
  -H 'Content-Type: application/json' \
  -d '{"name": "Trojan.Win32.Updated", "severity": "critical"}'
```

Коды ошибок

- `400`: невалидный запрос или MD5
- `404`: запись не найдена
- `409`: MD5 уже есть
- `413`: тело больше 1 MiB
- `500`: внутренняя ошибка

Ошибки приходят в `ErrorResponse` с полями `message` и `details`

Кроме API есть два служебных эндпоинта

- `GET /livez`: процесс жив
- `GET /readyz`: база доступна

## Как устроено

```
cmd/server                  запуск, конфиг, graceful shutdown
internal/api                роутер, middleware, ошибки
internal/api/generated      сгенерированный код, руками не править
internal/service            бизнес-логика, дефолты, валидация
internal/domain             модель угрозы и правила
internal/store              интерфейс хранилища, PostgreSQL, миграции
internal/store/migrations   SQL-схема, встроена через go:embed
internal/store/memory       хранилище в памяти для тестов
```

Слои идут внутрь: `api -> service -> store -> domain`
Транспортные типы не выходят за пределы пакета `api`
Сервис работает с доменной моделью
Ошибки `ErrNotFound`, `ErrConflict` и `ValidationError` превращаются в HTTP-ответы в `internal/api/handler.go`

## Тесты

```bash
make test               # unit и HTTP
make test-integration   # PostgreSQL в Docker
go vet ./...
gofmt -l .
```

Интеграционные тесты смотрят на `TEST_DATABASE_URL`
Если переменная пустая, тест пропускается
`make test-integration` сам поднимает `db` и выставляет URL
Проверяются миграции, CRUD, конфликт уникальности, nullable-поля и сохранение `created_at`

## Кодогенерация

Спецификация это источник истины
Сгенерированный код лежит в репозитории, поэтому для сборки генератор не нужен
Пересобрать можно так

```bash
make generate
```

Версия `oapi-codegen` зафиксирована в `Makefile` и `tools.go`

## Пара решений

- `md5` лежит в `varchar(32)` с CHECK на нижний регистр, API принимает верхний и нормализует
- enum-поля дополнительно ограничены CHECK в базе, чтобы данные не портились в обход API
- миграции идут под `pg_advisory_lock`, поэтому реплики могут стартовать одновременно
- `/livez` не зависит от базы, а `/readyz` проверяет соединение
- `PUT` сделан полной заменой, как написано в исходной спецификации
- из защиты есть параметризованные SQL-запросы, non-root в контейнере, лимит тела, таймауты и recoverer
- auth, rate-limit и TLS не добавлял, в задании это плюс, а не обязательная часть
