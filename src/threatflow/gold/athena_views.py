"""Deploy the versioned ThreatFlow Athena views in deterministic order."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

_CLIENT_CONFIG = Config(
    retries={"total_max_attempts": 6, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
    max_pool_connections=10,
)
_VIEW_STATEMENT = re.compile(
    r"^\s*CREATE\s+OR\s+REPLACE\s+VIEW\s+"
    r"(?P<database>[A-Za-z_][A-Za-z0-9_]*)\."
    r"(?P<view>[A-Za-z_][A-Za-z0-9_]*)\s+AS\b",
    re.IGNORECASE,
)
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "CANCELLED"}


class AthenaViewDeploymentError(RuntimeError):
    """Raised when a view deployment is unsafe or an Athena query fails."""


@dataclass(frozen=True)
class AthenaViewDefinition:
    order: int
    name: str
    path: Path
    sql: str


@dataclass(frozen=True)
class AthenaViewResult:
    name: str
    status: Literal["PLANNED", "DEPLOYED"]
    query_execution_id: str | None


@dataclass(frozen=True)
class AthenaViewDeploymentResult:
    database: str
    workgroup: str
    views: tuple[AthenaViewResult, ...]


class AthenaViewDeployer:
    def __init__(
        self,
        *,
        database: str,
        workgroup: str,
        athena_client: Any,
        glue_client: Any,
        poll_interval_seconds: float = 2,
        timeout_seconds: float = 300,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not database.strip() or not workgroup.strip():
            raise ValueError("database and workgroup must not be empty")
        if poll_interval_seconds < 0 or timeout_seconds <= 0:
            raise ValueError("poll interval must be non-negative and timeout must be positive")
        self.database = database
        self.workgroup = workgroup
        self.athena = athena_client
        self.glue = glue_client
        self.poll_interval_seconds = poll_interval_seconds
        self.timeout_seconds = timeout_seconds
        self.sleep = sleep

    def deploy(self, views_dir: Path, *, dry_run: bool = False) -> AthenaViewDeploymentResult:
        definitions = load_view_definitions(views_dir, database=self.database)
        if dry_run:
            return AthenaViewDeploymentResult(
                database=self.database,
                workgroup=self.workgroup,
                views=tuple(AthenaViewResult(item.name, "PLANNED", None) for item in definitions),
            )

        results = []
        for definition in definitions:
            response = self.athena.start_query_execution(
                QueryString=definition.sql,
                QueryExecutionContext={"Database": self.database, "Catalog": "AwsDataCatalog"},
                WorkGroup=self.workgroup,
            )
            query_execution_id = response.get("QueryExecutionId")
            if not isinstance(query_execution_id, str) or not query_execution_id:
                raise AthenaViewDeploymentError(
                    f"Athena returned no query execution ID for view {definition.name}"
                )
            self._wait_for_query(query_execution_id, definition.name)
            self._verify_view(definition.name)
            results.append(AthenaViewResult(definition.name, "DEPLOYED", query_execution_id))
        return AthenaViewDeploymentResult(
            database=self.database,
            workgroup=self.workgroup,
            views=tuple(results),
        )

    def _wait_for_query(self, query_execution_id: str, view_name: str) -> None:
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            response = self.athena.get_query_execution(QueryExecutionId=query_execution_id)
            status = response.get("QueryExecution", {}).get("Status", {})
            state = status.get("State")
            if state in _TERMINAL_STATES:
                if state != "SUCCEEDED":
                    reason = status.get("StateChangeReason", "no failure reason returned")
                    raise AthenaViewDeploymentError(
                        f"Athena deployment failed for view {view_name}: {state}: {reason}"
                    )
                return
            if time.monotonic() >= deadline:
                self.athena.stop_query_execution(QueryExecutionId=query_execution_id)
                raise AthenaViewDeploymentError(
                    f"Athena deployment timed out for view {view_name} after "
                    f"{self.timeout_seconds:g} seconds"
                )
            self.sleep(self.poll_interval_seconds)

    def _verify_view(self, view_name: str) -> None:
        response = self.glue.get_table(DatabaseName=self.database, Name=view_name)
        table = response.get("Table", {})
        if table.get("Name") != view_name or table.get("TableType") != "VIRTUAL_VIEW":
            raise AthenaViewDeploymentError(
                f"Glue Catalog did not expose {self.database}.{view_name} as a VIRTUAL_VIEW"
            )


def load_view_definitions(views_dir: Path, *, database: str) -> tuple[AthenaViewDefinition, ...]:
    if not views_dir.is_dir():
        raise AthenaViewDeploymentError(f"Athena views directory does not exist: {views_dir}")
    definitions = []
    for path in sorted(views_dir.glob("*.sql")):
        prefix, separator, _ = path.name.partition("_")
        if not separator or not prefix.isdigit():
            raise AthenaViewDeploymentError(
                f"Athena view filename must start with a numeric order: {path.name}"
            )
        sql = path.read_text(encoding="utf-8").strip()
        sql_without_line_comments = re.sub(r"--[^\n]*(?:\n|$)", "\n", sql)
        match = _VIEW_STATEMENT.search(sql_without_line_comments)
        if match is None:
            raise AthenaViewDeploymentError(
                f"Athena view file is not CREATE OR REPLACE VIEW: {path.name}"
            )
        statement_database = match.group("database")
        if statement_database.lower() != database.lower():
            raise AthenaViewDeploymentError(
                f"Athena view {path.name} targets database {statement_database}, "
                f"expected {database}"
            )
        definitions.append(
            AthenaViewDefinition(
                order=int(prefix),
                name=match.group("view"),
                path=path,
                sql=sql,
            )
        )
    if not definitions:
        raise AthenaViewDeploymentError(f"no Athena view SQL files found in {views_dir}")
    orders = [item.order for item in definitions]
    names = [item.name.lower() for item in definitions]
    if len(orders) != len(set(orders)) or len(names) != len(set(names)):
        raise AthenaViewDeploymentError("Athena view order and names must be unique")
    return tuple(sorted(definitions, key=lambda item: (item.order, item.name)))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy versioned ThreatFlow Athena views in deterministic order."
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--workgroup", required=True)
    parser.add_argument("--region", default=None)
    parser.add_argument(
        "--views-dir",
        type=Path,
        default=Path("analytics/athena/views"),
        help="Directory containing numerically ordered CREATE OR REPLACE VIEW files.",
    )
    parser.add_argument("--poll-interval-seconds", type=float, default=2)
    parser.add_argument("--timeout-seconds", type=float, default=300)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        session = None if args.dry_run else boto3.Session(region_name=args.region)
        deployer = AthenaViewDeployer(
            database=args.database,
            workgroup=args.workgroup,
            athena_client=(
                session.client("athena", config=_CLIENT_CONFIG) if session is not None else None
            ),
            glue_client=(
                session.client("glue", config=_CLIENT_CONFIG) if session is not None else None
            ),
            poll_interval_seconds=args.poll_interval_seconds,
            timeout_seconds=args.timeout_seconds,
        )
        result = deployer.deploy(args.views_dir, dry_run=args.dry_run)
    except (AthenaViewDeploymentError, ClientError, ValueError) as exc:
        print(f"Athena view deployment failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
