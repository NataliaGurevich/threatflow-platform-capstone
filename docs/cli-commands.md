# ThreatFlow CLI: справочник команд

Рекомендуемый способ запуска ThreatFlow CLI — через Docker Compose. Так команда
использует то же окружение и те же настройки, что и остальные сервисы проекта.

## Основные команды

| Команда | Назначение | Что читает | Что изменяет | Важная информация |
| --- | --- | --- | --- | --- |
| `docker compose run --rm threatflow-cli help` | Показывает список доступных команд | Ничего | Ничего | Безопасная команда |
| `docker compose run --rm threatflow-cli backfill ...` | Запускает историческую загрузку через Airflow | Аргументы, `.env`, checkpoint | Создаёт Airflow runs, обновляет checkpoint, загружает raw и данные в PostgreSQL | Сначала используйте `--dry-run`; для разных планов нужны разные checkpoint-файлы |
| `docker compose run --rm --no-deps threatflow-cli backfill-status ...` | Показывает прогресс backfill | Только checkpoint JSON | Ничего | Read-only; работает без Airflow и PostgreSQL |
| `docker compose run --rm threatflow-cli rebuild-cisa-changes` | Перестраивает историю изменений CISA из сохранённых raw snapshots | `raw_artifacts` и raw-файлы CISA | Атомарно заменяет содержимое `cisa_kev_changes` | Не загружает данные из интернета; исходные raw-файлы не изменяет |
| `docker compose run --rm --no-deps threatflow-cli backup-databases` | Создаёт backups `treat_flow` и `metabase` | Обе PostgreSQL-базы и `.env` | Создаёт `.dump` и `.sha256` в `data/backups` | PostgreSQL уже должен работать; Airflow не требуется; ничего не удаляет |

## Исторический backfill

Сначала выполните безопасный предварительный просмотр:

```bash
docker compose run --rm threatflow-cli backfill \
  --sources nvd epss \
  --start 2025-01-01 \
  --end 2025-01-31 \
  --nvd-mode modified \
  --checkpoint /opt/threatflow/data/my-backfill.json \
  --dry-run
```

После проверки плана уберите `--dry-run`:

```bash
docker compose run --rm threatflow-cli backfill \
  --sources nvd epss \
  --start 2025-01-01 \
  --end 2025-01-31 \
  --nvd-mode modified \
  --checkpoint /opt/threatflow/data/my-backfill.json
```

| Аргумент | Значение | Важная информация |
| --- | --- | --- |
| `--sources` | `nvd`, `cisa`, `epss` | Можно указать несколько источников |
| `--start` | Начальная дата | Формат `YYYY-MM-DD` |
| `--end` | Конечная дата | Диапазон включительный |
| `--nvd-mode modified` | Изменения NVD за период | Рекомендуется для восстановления пропусков |
| `--nvd-mode published` | CVE, опубликованные за период | Не восстанавливает последующие модификации |
| `--interval-days` | Размер внешнего окна | По умолчанию 31 день |
| `--chunk-days` | Размер NVD-чанка | Должен соблюдать ограничения NVD API |
| `--checkpoint` | Файл состояния | Один checkpoint должен использоваться только для одного неизменного плана |
| `--dry-run` | Только показать план | Не подключается к Airflow и ничего не изменяет |

## Backfill status

```bash
docker compose run --rm --no-deps threatflow-cli backfill-status \
  --checkpoint /opt/threatflow/data/my-backfill.json \
  --stall-after-minutes 30
```

| Статус | Значение |
| --- | --- |
| `RUNNING` | Есть активное окно, heartbeat свежий |
| `STALLED` | Heartbeat старше установленного порога |
| `FAILED` | Активный Airflow run записан как неуспешный |
| `COMPLETED` | Все окна завершены, активного окна нет |
| `UNKNOWN` | Состояние checkpoint нельзя надёжно классифицировать |

### Exit codes `backfill-status`

| Код | Значение |
| ---: | --- |
| `0` | `RUNNING` или `COMPLETED` |
| `1` | `FAILED` |
| `2` | `STALLED`, `UNKNOWN` или некорректный ввод |

Посмотреть exit code последней команды:

```bash
echo $?
```

## Перестроение истории CISA

```bash
docker compose run --rm threatflow-cli rebuild-cisa-changes
```

Команда:

- не обращается к GitHub;
- читает уже сохранённые CISA snapshots;
- строит события `baseline`, `added`, `modified` и `removed`;
- заменяет производную таблицу в одной транзакции;
- безопасна для повторного запуска;
- не удаляет raw-файлы.

Это операция записи в PostgreSQL. Таблица `cisa_kev_changes` является производной и
может быть заново построена из raw snapshots.

## Database backup

```bash
docker compose run --rm --no-deps threatflow-cli backup-databases
```

Результат:

```text
data/backups/
├── treat_flow-<UTC timestamp>.dump
├── treat_flow-<UTC timestamp>.dump.sha256
├── metabase-<UTC timestamp>.dump
└── metabase-<UTC timestamp>.dump.sha256
```

| Аргумент | По умолчанию | Назначение |
| --- | --- | --- |
| `--output-dir` | `/opt/threatflow/data/backups` | Папка внутри CLI-контейнера |
| `--metabase-database` | `METABASE_DB_NAME` или `metabase` | Имя базы Metabase |
| `--connect-timeout-seconds` | `10` | Timeout подключения к PostgreSQL |

### Exit codes `backup-databases`

| Код | Значение |
| ---: | --- |
| `0` | Обе базы успешно скопированы и проверены |
| `1` | Ошибка подключения, `pg_dump`, проверки или файловой системы |
| `2` | Некорректные CLI-аргументы |

Команда не копирует:

- `data/raw`;
- Airflow metadata;
- Airflow logs;
- `MB_ENCRYPTION_SECRET_KEY`;
- backups на внешний диск.

PostgreSQL должен быть запущен до выполнения команды. `--no-deps` намеренно не
запускает Airflow и другие зависимости.

## Retention report

Retention report является отдельным host-скриптом, а не командой контейнерного CLI:

```bash
./scripts/report-expired-database-backups.sh
```

| Свойство | Поведение |
| --- | --- |
| Retention | 14 дней |
| Поиск | Только `*.dump` |
| Raw archives | Не рассматриваются |
| Удаление | Никогда не выполняется |
| Результат | Список просроченных dumps и связанных checksums |

Изменить период только для одного запуска:

```bash
THREATFLOW_BACKUP_RETENTION_DAYS=30 \
  ./scripts/report-expired-database-backups.sh
```

## Флаги Docker Compose

| Флаг | Что означает |
| --- | --- |
| `run` | Создать одноразовый контейнер для команды |
| `--rm` | Удалить одноразовый контейнер после завершения; файлы в смонтированной `data` сохраняются |
| `--no-deps` | Не запускать зависимости Compose, например Airflow |
| `-T` | Отключить псевдотерминал; важно при перенаправлении бинарного dump |
| `exec` | Выполнить команду в уже работающем контейнере |

## Правила безопасного использования

1. Всегда запускайте большой backfill сначала с `--dry-run`.
2. Не используйте один checkpoint для разных диапазонов или наборов источников.
3. Не передавайте пароли через аргументы командной строки.
4. После database backup проверяйте `.sha256` и периодически выполняйте тестовое
   восстановление в отдельную базу.
5. Храните `MB_ENCRYPTION_SECRET_KEY` отдельно в менеджере паролей.
6. Копируйте проверенные backups на отдельный диск или во внешнее защищённое хранилище.
7. Не используйте `--remove-orphans` и destructive cleanup без проверки точных целей.
