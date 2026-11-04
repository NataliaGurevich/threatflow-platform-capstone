from threatflow.models import Base


def test_expected_business_and_operational_tables_are_defined() -> None:
    assert set(Base.metadata.tables) == {
        "cisa_kev_vulnerabilities",
        "nvd_cves",
        "epss_scores",
        "ingestion_checkpoints",
    }


def test_expected_primary_keys() -> None:
    assert [
        column.name for column in Base.metadata.tables["cisa_kev_vulnerabilities"].primary_key
    ] == ["cve_id"]
    assert [column.name for column in Base.metadata.tables["nvd_cves"].primary_key] == ["cve_id"]
    assert [column.name for column in Base.metadata.tables["epss_scores"].primary_key] == [
        "cve_id",
        "score_date",
    ]
    assert [
        column.name for column in Base.metadata.tables["ingestion_checkpoints"].primary_key
    ] == ["source"]
