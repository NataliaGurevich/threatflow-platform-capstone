"""Build normalized CISA KEV changes from immutable Git snapshots."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from threatflow.config import Settings
from threatflow.ingestion.cisa_parser import parse_catalog
from threatflow.models.cisa_change import CisaKevChange
from threatflow.models.raw_artifact import RawArtifact
from threatflow.raw_storage import create_raw_artifact_store


@dataclass(frozen=True)
class CisaChangesResult:
    snapshots: int
    baseline: int
    added: int
    modified: int
    removed: int


def json_safe_record(record: dict) -> dict:
    return {
        key: value.isoformat() if isinstance(value, (date, datetime)) else value
        for key, value in record.items()
    }


def calculate_changes(
    previous: dict[str, dict] | None,
    current: dict[str, dict],
    *,
    commit_sha: str,
    committed_at: datetime,
    revision_type: str = "git_commit",
) -> list[dict]:
    if previous is None:
        return [
            {
                "commit_sha": commit_sha,
                "revision_type": revision_type,
                "committed_at": committed_at,
                "cve_id": cve_id,
                "change_type": "baseline",
                "changed_fields": sorted(record),
                "previous_values": None,
                "current_values": record,
            }
            for cve_id, record in sorted(current.items())
        ]
    changes = []
    for cve_id in sorted(current.keys() - previous.keys()):
        changes.append(
            {
                "commit_sha": commit_sha,
                "revision_type": revision_type,
                "committed_at": committed_at,
                "cve_id": cve_id,
                "change_type": "added",
                "changed_fields": sorted(current[cve_id]),
                "previous_values": None,
                "current_values": current[cve_id],
            }
        )
    for cve_id in sorted(previous.keys() - current.keys()):
        changes.append(
            {
                "commit_sha": commit_sha,
                "revision_type": revision_type,
                "committed_at": committed_at,
                "cve_id": cve_id,
                "change_type": "removed",
                "changed_fields": sorted(previous[cve_id]),
                "previous_values": previous[cve_id],
                "current_values": None,
            }
        )
    for cve_id in sorted(previous.keys() & current.keys()):
        before, after = previous[cve_id], current[cve_id]
        changed_fields = sorted(
            key for key in before.keys() | after.keys() if before.get(key) != after.get(key)
        )
        if changed_fields:
            changes.append(
                {
                    "commit_sha": commit_sha,
                    "revision_type": revision_type,
                    "committed_at": committed_at,
                    "cve_id": cve_id,
                    "change_type": "modified",
                    "changed_fields": changed_fields,
                    "previous_values": {key: before.get(key) for key in changed_fields},
                    "current_values": {key: after.get(key) for key in changed_fields},
                }
            )
    return changes


def resolve_cisa_artifact_path(stored_path: str, raw_root: Path) -> Path:
    stored = Path(stored_path)
    if stored.exists():
        return stored
    parts = stored.parts
    try:
        source_index = parts.index("cisa_kev")
    except ValueError as exc:
        raise FileNotFoundError(f"cannot resolve CISA artifact path: {stored_path}") from exc
    candidate = raw_root.joinpath(*parts[source_index:])
    if not candidate.exists():
        raise FileNotFoundError(f"CISA artifact is missing: {candidate}")
    return candidate


def rebuild_cisa_changes(settings: Settings | None = None) -> CisaChangesResult:
    settings = settings or Settings()
    raw_store = create_raw_artifact_store(settings)
    engine = create_engine(settings.database_url)
    counts = {"baseline": 0, "added": 0, "modified": 0, "removed": 0}
    try:
        with Session(engine) as read_session:
            artifacts = read_session.scalars(
                select(RawArtifact)
                .where(
                    RawArtifact.source == "cisa_kev",
                    RawArtifact.request_mode.in_(("git_history", "snapshot")),
                )
                .order_by(
                    func.coalesce(RawArtifact.requested_start, RawArtifact.first_acquired_at),
                    RawArtifact.source_revision,
                    RawArtifact.sha256,
                )
            ).all()
        previous = None
        with engine.begin() as connection:
            session = Session(bind=connection)
            session.execute(delete(CisaKevChange))
            for artifact in artifacts:
                records = parse_catalog(raw_store.read(artifact.storage_path))
                current = {record["cve_id"]: json_safe_record(record) for record in records}
                is_git_revision = (
                    artifact.request_mode == "git_history" and artifact.source_revision is not None
                )
                changes = calculate_changes(
                    previous,
                    current,
                    commit_sha=(artifact.source_revision if is_git_revision else artifact.sha256),
                    committed_at=(
                        artifact.requested_start if is_git_revision else artifact.first_acquired_at
                    ),
                    revision_type=("git_commit" if is_git_revision else "content_sha256"),
                )
                for offset in range(0, len(changes), 1000):
                    session.execute(insert(CisaKevChange).values(changes[offset : offset + 1000]))
                for change in changes:
                    counts[change["change_type"]] += 1
                previous = current
            session.flush()
    finally:
        engine.dispose()
    return CisaChangesResult(len(artifacts), **counts)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rebuild cisa_kev_changes from validated immutable raw snapshots."
    )
    parser.parse_args()
    result = rebuild_cisa_changes()
    print(json.dumps(result.__dict__, sort_keys=True))


if __name__ == "__main__":
    main()
