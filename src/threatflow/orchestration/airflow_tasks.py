"""Airflow callables; ingestion runs in the application interpreter."""


def daily(source, interval_start, interval_end):
    import logging
    from dataclasses import asdict
    from datetime import datetime

    from threatflow.orchestration.ingestion_runner import run_daily

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("threatflow.airflow.daily")
    source = str(source).strip().lower()
    log.info(
        "stage=task_input source=%s interval_start=%r interval_end=%r",
        source,
        interval_start,
        interval_end,
    )
    try:
        start = datetime.fromisoformat(str(interval_start))
        end = datetime.fromisoformat(str(interval_end))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"invalid Airflow interval for source={source!r}: "
            f"start={interval_start!r}, end={interval_end!r}"
        ) from exc
    log.info("stage=ingestion_start source=%s", source)
    result = run_daily(source, start, end)
    log.info(
        "stage=ingestion_complete source=%s fetched=%d accepted=%d "
        "bronze_created=%d bronze_reused=%d",
        result.source,
        result.records_fetched,
        result.records_accepted,
        result.bronze_objects_created,
        result.bronze_objects_reused,
    )
    return asdict(result)


def validate(**context):
    from airflow.exceptions import AirflowFailException

    from threatflow.orchestration.ingestion_runner import validate_backfill

    p = context["params"]
    try:
        first, last = validate_backfill(p["sources"], p["start_date"], p["end_date"], p["nvd_mode"])
    except ValueError as exc:
        raise AirflowFailException(str(exc)) from exc
    return {
        "sources": p["sources"],
        "start_date": first.isoformat(),
        "end_date": last.isoformat(),
        "nvd_mode": p["nvd_mode"],
    }


def backfill_source(source, sources, start_date, end_date, nvd_mode, chunk_days):
    import logging
    from dataclasses import asdict
    from datetime import date

    from threatflow.orchestration.ingestion_runner import run_backfill

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    log = logging.getLogger("threatflow.airflow.backfill")
    log.info(
        "stage=backfill_input source=%s selected_sources=%s start=%s end=%s mode=%s",
        source,
        sources,
        start_date,
        end_date,
        nvd_mode,
    )
    if source not in sources:
        log.info("stage=backfill_skipped source=%s", source)
        return {"source": source, "skipped": True}
    log.info("stage=backfill_start source=%s", source)
    result = run_backfill(
        source,
        date.fromisoformat(start_date),
        date.fromisoformat(end_date),
        nvd_mode,
        int(chunk_days),
    )
    log.info(
        "stage=backfill_complete source=%s fetched=%d accepted=%d "
        "bronze_created=%d bronze_reused=%d",
        result.source,
        result.records_fetched,
        result.records_accepted,
        result.bronze_objects_created,
        result.bronze_objects_reused,
    )
    return asdict(result)
