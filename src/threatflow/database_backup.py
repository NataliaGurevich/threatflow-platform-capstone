"""Create and validate PostgreSQL database backups."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, TextIO

from threatflow.config import Settings

CommandRunner = Callable[..., subprocess.CompletedProcess[bytes]]


class BackupError(RuntimeError):
    """Raised when a safe backup cannot be created."""


@dataclass(frozen=True)
class PostgresConnection:
    """Connection values shared by pg_dump and pg_restore."""

    host: str
    port: int
    user: str
    password: str
    connect_timeout_seconds: int = 10

    def environment(self) -> dict[str, str]:
        """Return a subprocess environment without exposing the password in arguments."""
        environment = os.environ.copy()
        environment["PGPASSWORD"] = self.password
        environment["PGCONNECT_TIMEOUT"] = str(self.connect_timeout_seconds)
        return environment


@dataclass(frozen=True)
class BackupResult:
    """Paths published after one database dump passes validation."""

    database: str
    dump_path: Path
    checksum_path: Path


def create_database_backup(
    *,
    database: str,
    output_dir: Path,
    connection: PostgresConnection,
    timestamp: str,
    runner: CommandRunner | None = None,
) -> BackupResult:
    """Create, validate, checksum, and atomically publish one custom-format dump."""
    if not database:
        raise BackupError("database name must not be empty")
    if shutil.which("pg_dump") is None or shutil.which("pg_restore") is None:
        raise BackupError("pg_dump and pg_restore must be installed")

    run = runner or subprocess.run
    output_dir.mkdir(parents=True, exist_ok=True)
    label = _safe_filename_label(database)
    filename = f"{label}-{timestamp}.dump"
    dump_path = output_dir / filename
    checksum_path = output_dir / f"{filename}.sha256"
    temporary_dump_path = output_dir / f"{filename}.tmp"
    temporary_checksum_path = output_dir / f"{filename}.sha256.tmp"

    published_paths = (dump_path, checksum_path)
    if any(path.exists() for path in published_paths):
        raise BackupError(f"backup already exists for {database} at {timestamp}")

    temporary_paths = (temporary_dump_path, temporary_checksum_path)
    environment = connection.environment()

    try:
        with _open_private_binary_file(temporary_dump_path) as dump_file:
            run(
                [
                    "pg_dump",
                    "--host",
                    connection.host,
                    "--port",
                    str(connection.port),
                    "--username",
                    connection.user,
                    "--format=custom",
                    database,
                ],
                check=True,
                env=environment,
                stdout=dump_file,
            )

        run(
            ["pg_restore", "--list", str(temporary_dump_path)],
            check=True,
            env=environment,
            stdout=subprocess.DEVNULL,
        )

        digest = _sha256(temporary_dump_path)
        _write_private_text_file(
            temporary_checksum_path,
            f"{digest}  {filename}\n",
        )

        os.replace(temporary_dump_path, dump_path)
        os.replace(temporary_checksum_path, checksum_path)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BackupError(f"failed to back up database {database}: {exc}") from exc
    finally:
        for path in temporary_paths:
            path.unlink(missing_ok=True)

    return BackupResult(
        database=database,
        dump_path=dump_path,
        checksum_path=checksum_path,
    )


def backup_databases(
    *,
    databases: Sequence[str],
    output_dir: Path,
    connection: PostgresConnection,
    now: datetime | None = None,
    runner: CommandRunner | None = None,
) -> list[BackupResult]:
    """Back up databases sequentially with one shared UTC timestamp."""
    timestamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    return [
        create_database_backup(
            database=database,
            output_dir=output_dir,
            connection=connection,
            timestamp=timestamp,
            runner=runner,
        )
        for database in databases
    ]


def _safe_filename_label(database: str) -> str:
    label = re.sub(r"[^A-Za-z0-9_.-]+", "_", database).strip("._-")
    if not label:
        raise BackupError("database name cannot produce a safe backup filename")
    return label


def _open_private_binary_file(path: Path) -> BinaryIO:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "wb")


def _write_private_text_file(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        file.write(value)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main(
    argv: list[str] | None = None,
    *,
    output: TextIO = sys.stdout,
    error: TextIO = sys.stderr,
) -> int:
    """Run database backups for an operator or scheduler."""
    parser = argparse.ArgumentParser(
        description="Create validated backups for ThreatFlow and Metabase databases."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(os.environ.get("THREATFLOW_BACKUP_DIR", "data/backups")),
        help="directory for dump and checksum files",
    )
    parser.add_argument(
        "--metabase-database",
        default=os.environ.get("METABASE_DB_NAME", "metabase"),
        help="Metabase application database name",
    )
    parser.add_argument(
        "--connect-timeout-seconds",
        type=_positive_integer,
        default=10,
        help="PostgreSQL connection timeout",
    )
    args = parser.parse_args(argv)

    try:
        settings = Settings()
        password = settings.postgres_password.get_secret_value()
        if not password:
            raise BackupError("THREATFLOW_POSTGRES_PASSWORD must not be empty")
        if settings.postgres_db == args.metabase_database:
            raise BackupError("application and Metabase database names must differ")

        connection = PostgresConnection(
            host=settings.postgres_host,
            port=settings.postgres_port,
            user=settings.postgres_user,
            password=password,
            connect_timeout_seconds=args.connect_timeout_seconds,
        )
        results = backup_databases(
            databases=(settings.postgres_db, args.metabase_database),
            output_dir=args.output_dir,
            connection=connection,
        )
    except (BackupError, ValueError) as exc:
        print(f"Error: {exc}", file=error)
        return 1

    for result in results:
        print(f"Created: {result.dump_path}", file=output)
        print(f"Checksum: {result.checksum_path}", file=output)
    print("Database backups completed successfully.", file=output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
