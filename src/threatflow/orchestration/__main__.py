"""Run a bounded ingestion job without Airflow."""

import argparse
import logging
from datetime import UTC, date, datetime

from threatflow.orchestration.ingestion_runner import run_backfill, run_daily, validate_backfill


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    daily = sub.add_parser("daily")
    daily.add_argument("source", choices=("nvd", "cisa", "epss"))
    daily.add_argument("--start", required=True, type=datetime.fromisoformat)
    daily.add_argument("--end", required=True, type=datetime.fromisoformat)
    backfill = sub.add_parser("backfill")
    backfill.add_argument("source", choices=("nvd", "epss"))
    backfill.add_argument("--start", required=True, type=date.fromisoformat)
    backfill.add_argument("--end", required=True, type=date.fromisoformat)
    backfill.add_argument("--mode", default="published", choices=("published", "modified"))
    backfill.add_argument("--chunk-days", default=7, type=int)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.command == "daily":
        if args.start.tzinfo is None or args.end.tzinfo is None:
            parser.error("daily timestamps must include a timezone")
        result = run_daily(args.source, args.start.astimezone(UTC), args.end.astimezone(UTC))
    else:
        validate_backfill([args.source], args.start.isoformat(), args.end.isoformat(), args.mode)
        result = run_backfill(args.source, args.start, args.end, args.mode, args.chunk_days)
    print(result)


if __name__ == "__main__":
    main()
