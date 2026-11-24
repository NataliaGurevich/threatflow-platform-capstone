"""Regression tests for hermetic ThreatFlow configuration in pytest."""

from __future__ import annotations

import ast
from pathlib import Path

from threatflow.local_raw_storage import LocalRawArtifactStore
from threatflow.raw_storage import create_raw_artifact_store


def test_hidden_settings_factory_ignores_working_directory_dotenv(tmp_path, monkeypatch) -> None:
    (tmp_path / ".env").write_text(
        "THREATFLOW_RAW_STORAGE_BACKEND=s3\n"
        "THREATFLOW_S3_BRONZE_BUCKET=must-not-be-read\n"
    )
    monkeypatch.chdir(tmp_path)

    store = create_raw_artifact_store()

    assert isinstance(store, LocalRawArtifactStore)
    assert store.root == Path("data/raw")


def test_direct_settings_calls_in_tests_explicitly_disable_dotenv() -> None:
    tests_root = Path(__file__).parents[1]
    missing_guard: list[str] = []
    for path in sorted(tests_root.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_settings_call(node):
                continue
            env_file = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "_env_file"),
                None,
            )
            if not isinstance(env_file, ast.Constant) or env_file.value is not None:
                relative = path.relative_to(tests_root.parent)
                missing_guard.append(f"{relative}:{node.lineno}")

    assert missing_guard == [], (
        "Test Settings calls must include _env_file=None: " + ", ".join(missing_guard)
    )


def _is_settings_call(node: ast.Call) -> bool:
    return (isinstance(node.func, ast.Name) and node.func.id == "Settings") or (
        isinstance(node.func, ast.Attribute) and node.func.attr == "Settings"
    )
