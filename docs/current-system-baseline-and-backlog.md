# Baseline текущей системы и backlog этапов 1–2

Дата измерения: 2026-11-09. Среда: локальный Docker Compose development stack.
Измерения не являются production capacity forecast.

## 1. Baseline

### 1.1 Данные PostgreSQL

| Таблица | Фактические/оценочные строки | Полный размер relation |
| --- | ---: | ---: |
| `nvd_cves` | 420 597 фактически | 516 415 488 B |
| `cisa_kev_vulnerabilities` | 1 769 фактически | 40 681 472 B |
| `cisa_kev_changes` | ~2 007 | 5 070 848 B |
| `epss_scores` | 11 836 949 фактически | 2 183 888 896 B |
| `epss_current` | ~402 048 | 108 421 120 B |
| `epss_daily_summaries` | ~2 026 | 253 952 B |
| `raw_artifacts` | 3 683 фактически | 2 334 720 B |
| `ingestion_checkpoints` | ~1 | 24 576 B |

Примечание: `~` означает `pg_stat_user_tables.n_live_tup`; остальные counts
получены точным `count(*)`.

### 1.2 Coverage

- EPSS: 30 source dates, 2026-10-10…2026-11-08, 11 836 949 rows.
- NVD: 420 597 CVE; earliest publication 1999-01-01; latest stored modification
  2026-11-09 02:17 UTC.
- CISA KEV: 1 769 current rows; `date_added` 2021-11-03…2026-11-06.
- Raw manifest: 3 683 unique source/hash records; declared artifact bytes
  4 151 730 269.
- Raw filesystem: 4 052 files; `du` 5 295 296 KiB (около 5.05 GiB).

Разница manifest bytes и filesystem usage ожидаема до отдельной проверки:
filesystem включает allocation overhead и artifacts, которые могут не иметь
однозначного manifest row. Этап 0 должен добавить reconciliation по path/hash.

### 1.3 Airflow history

| DAG | Success | Failed | Средняя завершённая длительность | Максимум |
| --- | ---: | ---: | ---: | ---: |
| `nvd_daily` | 9 | 7 | 414 s | 4 038 s |
| `cisa_daily` | 1 564 | 219 | 3 s | 639 s |
| `epss_daily` | 13 | 3 | 556 s | 6 176 s |

Это вся сохранённая development metadata, включая manual/retry/test runs; её
нельзя интерпретировать как production success rate без классификации run type и
периода. Baseline показывает необходимость метрик по scheduled interval и stage.

### 1.4 Риски, выявленные baseline

1. `epss_scores` уже занимает основную часть application database и растёт
   ежедневно — первый Silver migration candidate.
2. Raw storage превышает 5 GiB и привязан к одному host — первый storage migration
   candidate.
3. Длительность EPSS/NVD имеет большой разброс — нужны stage timings и bytes/rows
   throughput до выбора Glue/Fargate sizing.
4. Airflow history смешивает scheduled, manual, retry и test runs.
5. Не измерены query frequency/bytes scanned Metabase и recovery time.

## 2. Stage 0 exit checklist

- [x] Сняты table counts/sizes и date coverage.
- [x] Сняты Raw file count/size и manifest totals.
- [x] Сняты базовые Airflow run counts/durations.
- [ ] Добавлен reproducible read-only baseline script/report.
- [ ] Сверены filesystem artifacts ↔ `raw_artifacts` по path/hash.
- [ ] Зафиксированы p50/p95 ingestion stage durations на 7+ scheduled runs.
- [ ] Измерены fetched/validated/written/unchanged/rejected по источникам.
- [ ] Измерены основные Metabase query latency и query frequency.
- [ ] Выполнен и измерен restore application DB + Raw artifact.
- [ ] Подтверждены RPO/RTO, AWS Region, budget ceiling и retention.

Stage 0 считается завершённым после выполнения всех пунктов, а не только после
снятия разового snapshot.

## 3. Backlog этапа 1 — отделить storage от ingestion

### B1-01. Контракт `RawArtifactStore` — P0

**Работа:** определить `store(source, content, acquired_at, extension, metadata)`
и результат с URI/path, SHA-256, bytes и `created`. Не включать AWS SDK в contract.

**Acceptance criteria:**

- local implementation проходит существующие raw-storage tests;
- invalid source/extension отклоняются до write;
- exact bytes и SHA-256 не меняются;
- повторный write content-addressed artifact идемпотентен;
- ingestion не зависит от `pathlib.Path` конкретного backend.

### B1-02. Local adapter без изменения поведения — P0

**Работа:** обернуть текущий `store_raw_artifact` новым интерфейсом.

**Acceptance criteria:** существующие paths, partition layout, atomic rename,
permissions и tests сохраняются; migrations не требуются.

### B1-03. Перевести EPSS ingestion — P0

**Acceptance criteria:** Raw фиксируется до parse/database write; invalid archive
не меняет normalized tables; repeat безопасен; результат содержит backend-neutral
artifact URI; unit и PostgreSQL integration tests проходят.

### B1-04. Перевести CISA ingestion и watcher — P0

**Acceptance criteria:** `cisa_daily`, watcher и Git backfill используют общий
storage contract; watcher не удаляет/не заменяет daily functionality; новый hash
передаётся существующему ingestion без второго download; unchanged hash не
обновляет current state; invalid catalog propagates failure. До S3 watcher
сохраняет exact bytes в локальный content-addressed Raw storage и синхронно
передаёт pointer-only `CisaArtifactObserved` локальному handler.

Локальный scheduler реализован отдельным `cisa_watcher_hourly` DAG с расписанием
`0 * * * *`. `cisa_daily` сохраняется без изменений как daily recovery path; оба
DAG используют `cisa_api_pool` с одним slot.

### B1-05. Перевести NVD ingestion — P0

**Acceptance criteria:** каждая page сохраняется до parse; partial pagination не
продвигает checkpoint; replay не регрессирует CVE; page/window metadata входит в
manifest.

### B1-06. `RawArtifactCreated` envelope — P1

**Acceptance criteria:** versioned JSON schema содержит source, artifact URI,
SHA-256, acquisition/source time, request metadata, run ID и schema version;
dataset bytes отсутствуют; serialization round-trip покрыт tests.

### B1-07. Contract/failure tests — P0

Проверить permission error, interrupted write, duplicate, checksum mismatch,
database failure после Raw write и retry после failure.

**Stage 1 exit:** все три ingestion paths работают с local adapter; source logic
не знает physical storage; полный unit/integration regression PASS.

## 4. Backlog этапа 2 — AWS foundation и S3 Bronze

### B2-01. ADR и IaC skeleton — P0

**Acceptance criteria:** выбран CDK или Terraform; dev environment воспроизводим;
resources tagged; naming/account/region documented; `plan/diff` не содержит
необъяснимых replacements.

### B2-02. S3 layout и retention — P0

Определить Bronze/quarantine/Silver/Gold/Athena-results prefixes или buckets.

**Acceptance criteria:** Block Public Access; owner-enforced access; encryption;
Bronze versioning; lifecycle rules документированы и протестированы на non-prod;
Silver/Gold output не может повторно вызвать Bronze event rule.

### B2-03. IAM/KMS boundaries — P0

**Acceptance criteria:** acquisition пишет только Bronze; transform читает Bronze
и пишет Silver/Gold; Athena читает curated data и пишет только results; policies
ограничены resource ARN, `SourceArn`/`SourceAccount`; negative access tests PASS;
секретов в repository нет.

### B2-04. S3 `RawArtifactStore` — P0

**Acceptance criteria:** exact bytes, checksum и content type записываются;
результат содержит bucket/key/version ID; retry идемпотентен; SDK/network errors
propagate; multipart/incomplete writes не публикуются как success; mocked tests не
требуют production credentials.

### B2-05. Расширить Raw manifest — P0

Добавить backend-neutral URI и при необходимости bucket/key/version ID, сохранив
совместимость с `storage_path` на время миграции.

**Acceptance criteria:** versioned migration; local rows остаются читаемыми; S3
identity уникальна; повторное событие разрешается в тот же manifest; downgrade и
rollback documented.

### B2-06. Configurable rollout и dual observation — P0

**Acceptance criteria:** backend выбирается configuration; default остаётся local
до cutover; один source включается за раз (EPSS → CISA → NVD); counts/hashes/bytes
сверяются; переключение назад не требует data deletion.

### B2-07. Security и observability — P1

**Acceptance criteria:** CloudTrail data events или согласованное access logging;
CloudWatch error/request metrics; encrypted logs; budget alerts; alarms на upload
failure и отсутствие ожидаемого artifact; runbook для AccessDenied/KMS failure.

### B2-08. S3 reconciliation и recovery drill — P0

**Acceptance criteria:** report сверяет manifest ↔ S3 head/checksum; выбранный Raw
artifact читается и replayed; deleted/overwritten object восстанавливается через
versioning в dev drill; documented RTO measurement.

**Stage 2 exit:** три источника устойчиво пишут immutable Raw в S3; manifests и
checksums сверены; local rollback проверен; normalized/current processing не
изменило результаты.

## 5. Рекомендуемый порядок ближайших работ

1. Завершить tests и документацию additive CISA watcher.
2. Реализовать B1-01/B1-02 без AWS dependency.
3. Перевести EPSS (B1-03), затем CISA/watcher (B1-04), затем NVD (B1-05).
4. Закрыть Stage 0 measurements параллельно минимум за семь scheduled runs.
5. Принять ADR B2-01 и только затем создавать AWS resources.
6. Реализовать S3 adapter и включать sources по одному с reconciliation.

