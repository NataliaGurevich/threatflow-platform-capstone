from __future__ import annotations

import hashlib
import io
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from threatflow.database_backup import (
    BackupError,
    PostgresConnection,
    backup_databases,
    create_database_backup,
)


def _connection() -> PostgresConnection:
    return PostgresConnection(
        host="postgres",
        port=5432,
        user="threatflow",
        password="not-logged",
    )


def test_backup_databases_creates_validated_dumps_and_checksums(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr("threatflow.database_backup.shutil.which", lambda command: command)

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((command, kwargs))
        if command[0] == "pg_dump":
            dump_file = kwargs["stdout"]
            assert hasattr(dump_file, "write")
            dump_file.write(b"custom-format-backup")
        return subprocess.CompletedProcess(command, 0)

    results = backup_databases(
        databases=("threatflow", "metabase"),
        output_dir=tmp_path,
        connection=_connection(),
        now=datetime(2026, 11, 5, 19, 38, 7, tzinfo=UTC),
        runner=fake_run,
    )

    assert [result.database for result in results] == ["threatflow", "metabase"]
    assert [result.dump_path.name for result in results] == [
        "threatflow-2026-11-05T193807Z.dump",
        "metabase-2026-11-05T193807Z.dump",
    ]
    expected_digest = hashlib.sha256(b"custom-format-backup").hexdigest()
    for result in results:
        assert result.dump_path.read_bytes() == b"custom-format-backup"
        assert result.checksum_path.read_text() == (f"{expected_digest}  {result.dump_path.name}\n")
        assert result.dump_path.stat().st_mode & 0o777 == 0o600
        assert result.checksum_path.stat().st_mode & 0o777 == 0o600

    assert [command[0] for command, _ in calls] == [
        "pg_dump",
        "pg_restore",
        "pg_dump",
        "pg_restore",
    ]
    pg_dump_environment = calls[0][1]["env"]
    assert isinstance(pg_dump_environment, dict)
    assert pg_dump_environment["PGPASSWORD"] == "not-logged"
    assert "not-logged" not in calls[0][0]


def test_failed_dump_removes_temporary_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("threatflow.database_backup.shutil.which", lambda command: command)

    def failing_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        dump_file = kwargs["stdout"]
        assert hasattr(dump_file, "write")
        dump_file.write(b"incomplete")
        raise subprocess.CalledProcessError(1, command)

    with pytest.raises(BackupError, match="failed to back up database threatflow"):
        create_database_backup(
            database="threatflow",
            output_dir=tmp_path,
            connection=_connection(),
            timestamp="2026-11-05T193807Z",
            runner=failing_run,
        )

    assert list(tmp_path.iterdir()) == []


def test_failed_validation_removes_temporary_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("threatflow.database_backup.shutil.which", lambda command: command)

    def failing_validation(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        if command[0] == "pg_dump":
            dump_file = kwargs["stdout"]
            assert hasattr(dump_file, "write")
            dump_file.write(b"invalid-archive")
            return subprocess.CompletedProcess(command, 0)
        raise subprocess.CalledProcessError(1, command)

    with pytest.raises(BackupError, match="failed to back up database threatflow"):
        create_database_backup(
            database="threatflow",
            output_dir=tmp_path,
            connection=_connection(),
            timestamp="2026-11-05T193807Z",
            runner=failing_validation,
        )

    assert list(tmp_path.iterdir()) == []


def test_existing_backup_is_not_overwritten(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("threatflow.database_backup.shutil.which", lambda command: command)
    existing = tmp_path / "threatflow-2026-11-05T193807Z.dump"
    existing.write_bytes(b"keep-me")

    with pytest.raises(BackupError, match="backup already exists"):
        create_database_backup(
            database="threatflow",
            output_dir=tmp_path,
            connection=_connection(),
            timestamp="2026-11-05T193807Z",
        )

    assert existing.read_bytes() == b"keep-me"


def test_main_reports_missing_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EmptyPasswordSettings:
        postgres_password = SecretStr("")

    monkeypatch.setattr("threatflow.database_backup.Settings", EmptyPasswordSettings)
    output = io.StringIO()
    error = io.StringIO()

    from threatflow.database_backup import main

    assert main([], output=output, error=error) == 1
    assert output.getvalue() == ""
    assert "THREATFLOW_POSTGRES_PASSWORD must not be empty" in error.getvalue()
