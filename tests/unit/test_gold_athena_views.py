from pathlib import Path

import pytest

from threatflow.gold.athena_views import (
    AthenaViewDeployer,
    AthenaViewDeploymentError,
    load_view_definitions,
)


class FakeAthena:
    def __init__(self, states=None):
        self.states = list(states or ["SUCCEEDED"])
        self.started = []
        self.stopped = []

    def start_query_execution(self, **request):
        self.started.append(request)
        return {"QueryExecutionId": f"query-{len(self.started)}"}

    def get_query_execution(self, *, QueryExecutionId):
        del QueryExecutionId
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        status = {"State": state}
        if state in {"FAILED", "CANCELLED"}:
            status["StateChangeReason"] = "test failure"
        return {"QueryExecution": {"Status": status}}

    def stop_query_execution(self, *, QueryExecutionId):
        self.stopped.append(QueryExecutionId)


class FakeGlue:
    def __init__(self, table_type="VIRTUAL_VIEW"):
        self.table_type = table_type
        self.calls = []

    def get_table(self, *, DatabaseName, Name):
        self.calls.append((DatabaseName, Name))
        return {"Table": {"Name": Name, "TableType": self.table_type}}


def write_view(directory: Path, filename: str, name: str) -> None:
    directory.joinpath(filename).write_text(
        f"CREATE OR REPLACE VIEW threatflow_gold.{name} AS SELECT 1 AS value;\n"
    )


def test_loads_repository_views_in_numeric_dependency_order() -> None:
    definitions = load_view_definitions(
        Path("analytics/athena/views"), database="threatflow_gold"
    )

    assert [item.order for item in definitions] == [1, 2, 3, 4, 5, 6]
    assert definitions[0].name == "current_vulnerability_priority"
    assert definitions[-1].name == "kev_vendor_exposure_current"


def test_deploys_each_view_and_verifies_catalog(tmp_path: Path) -> None:
    write_view(tmp_path, "02_second.sql", "second_view")
    write_view(tmp_path, "01_first.sql", "first_view")
    athena = FakeAthena()
    glue = FakeGlue()
    deployer = AthenaViewDeployer(
        database="threatflow_gold",
        workgroup="admin",
        athena_client=athena,
        glue_client=glue,
        poll_interval_seconds=0,
        sleep=lambda _: None,
    )

    result = deployer.deploy(tmp_path)

    assert [item.name for item in result.views] == ["first_view", "second_view"]
    assert all(item.status == "DEPLOYED" for item in result.views)
    assert [request["WorkGroup"] for request in athena.started] == ["admin", "admin"]
    assert glue.calls == [
        ("threatflow_gold", "first_view"),
        ("threatflow_gold", "second_view"),
    ]


def test_dry_run_validates_without_aws_calls(tmp_path: Path) -> None:
    write_view(tmp_path, "01_first.sql", "first_view")
    athena = FakeAthena()
    glue = FakeGlue()

    result = AthenaViewDeployer(
        database="threatflow_gold",
        workgroup="admin",
        athena_client=athena,
        glue_client=glue,
    ).deploy(tmp_path, dry_run=True)

    assert result.views[0].status == "PLANNED"
    assert athena.started == []
    assert glue.calls == []


def test_stops_after_failed_view(tmp_path: Path) -> None:
    write_view(tmp_path, "01_first.sql", "first_view")
    deployer = AthenaViewDeployer(
        database="threatflow_gold",
        workgroup="admin",
        athena_client=FakeAthena(["FAILED"]),
        glue_client=FakeGlue(),
        poll_interval_seconds=0,
        sleep=lambda _: None,
    )

    with pytest.raises(AthenaViewDeploymentError, match="FAILED: test failure"):
        deployer.deploy(tmp_path)


@pytest.mark.parametrize(
    ("filename", "sql", "message"),
    [
        ("view.sql", "CREATE OR REPLACE VIEW threatflow_gold.a AS SELECT 1", "numeric"),
        ("01_view.sql", "DROP VIEW threatflow_gold.a", "not CREATE OR REPLACE"),
        (
            "01_view.sql",
            "CREATE OR REPLACE VIEW other_database.a AS SELECT 1",
            "targets database other_database",
        ),
    ],
)
def test_rejects_unsafe_view_files(
    tmp_path: Path, filename: str, sql: str, message: str
) -> None:
    tmp_path.joinpath(filename).write_text(sql)

    with pytest.raises(AthenaViewDeploymentError, match=message):
        load_view_definitions(tmp_path, database="threatflow_gold")
