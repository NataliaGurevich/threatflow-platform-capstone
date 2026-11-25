"""Manual bounded NVD/CISA/EPSS historical ingestion."""

from datetime import UTC, datetime, timedelta

from airflow.providers.standard.operators.python import ExternalPythonOperator, PythonOperator
from airflow.sdk import DAG, Param

from threatflow.orchestration.airflow_notifications import notify_task_failure
from threatflow.orchestration.airflow_tasks import backfill_source, validate

with DAG(
    dag_id="threat_intel_backfill",
    schedule=None,
    start_date=datetime(2025, 1, 1, tzinfo=UTC),
    catchup=False,
    max_active_runs=1,
    default_args={
        "retries": 2,
        "retry_delay": timedelta(minutes=5),
        "on_failure_callback": notify_task_failure,
    },
    params={
        "sources": Param(
            ["nvd"],
            type="array",
            minItems=1,
            uniqueItems=True,
            items={"type": "string", "enum": ["nvd", "cisa", "epss"]},
        ),
        "start_date": Param("2025-01-01", type="string", format="date"),
        "end_date": Param("2025-01-01", type="string", format="date"),
        "nvd_mode": Param("published", type="string", enum=["published", "modified"]),
        "chunk_days": Param(7, type="integer", minimum=1, maximum=31),
    },
    tags=["threatflow"],
    render_template_as_native_obj=True,
) as dag:
    check = PythonOperator(
        task_id="validate_parameters",
        python_callable=validate,
        execution_timeout=timedelta(minutes=1),
        retries=0,
    )
    for source in ("nvd", "cisa", "epss"):
        check >> ExternalPythonOperator(
            task_id=f"ingest_{source}",
            python_callable=backfill_source,
            op_kwargs={
                "source": source,
                "sources": "{{ params.sources }}",
                "start_date": "{{ params.start_date }}",
                "end_date": "{{ params.end_date }}",
                "nvd_mode": "{{ params.nvd_mode }}",
                "chunk_days": "{{ params.chunk_days }}",
            },
            python="/opt/threatflow-venv/bin/python",
            expect_airflow=False,
            pool=f"{source}_api_pool",
            execution_timeout=timedelta(hours=12),
        )
