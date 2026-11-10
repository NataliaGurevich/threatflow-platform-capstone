"""DAG contract checks run when the Airflow image supplies Airflow 3.1."""

from pathlib import Path

import pytest


def test_all_dags_parse_and_use_external_interpreter():
    pytest.importorskip("airflow.models.dagbag")
    from airflow.models.dagbag import DagBag
    from airflow.providers.standard.operators.python import ExternalPythonOperator

    folder = Path(__file__).resolve().parents[2] / "airflow" / "dags"
    bag = DagBag(dag_folder=str(folder), include_examples=False)
    assert not bag.import_errors
    assert set(bag.dags) == {
        "nvd_daily",
        "cisa_daily",
        "cisa_watcher_hourly",
        "epss_daily",
        "threat_intel_backfill",
    }
    expected = {"nvd_daily": "0 3 * * *", "cisa_daily": "0 4 * * *", "epss_daily": "0 6 * * *"}
    for dag_id, schedule in expected.items():
        dag = bag.dags[dag_id]
        assert not dag.catchup
        assert dag.timetable.summary == schedule
        task = dag.tasks[0]
        assert isinstance(task, ExternalPythonOperator)
        assert task.pool == f"{dag_id.split('_')[0]}_api_pool"
        assert task.python == "/opt/threatflow-venv/bin/python"
        assert task.expect_airflow is False
        assert "dag_run.run_after" in task.op_kwargs["interval_start"]
        assert "dag_run.run_after" in task.op_kwargs["interval_end"]
    watcher = bag.dags["cisa_watcher_hourly"]
    assert not watcher.catchup
    assert watcher.timetable.summary == "0 * * * *"
    assert watcher.max_active_runs == 1
    watcher_task = watcher.get_task("watch_cisa")
    assert isinstance(watcher_task, ExternalPythonOperator)
    assert watcher_task.pool == "cisa_api_pool"
    assert watcher_task.python == "/opt/threatflow-venv/bin/python"
    assert watcher_task.expect_airflow is False
    backfill = bag.dags["threat_intel_backfill"]
    assert not backfill.catchup
    assert backfill.schedule is None
    for source in ("nvd", "cisa", "epss"):
        task = backfill.get_task(f"ingest_{source}")
        assert isinstance(task, ExternalPythonOperator)
        assert task.pool == f"{source}_api_pool"
        assert task.expect_airflow is False
