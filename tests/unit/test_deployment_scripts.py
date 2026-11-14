import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "script",
    [
        Path("scripts/rebuild-airflow.sh"),
        Path("scripts/release-aws-lambdas.sh"),
    ],
)
def test_deployment_script_has_valid_bash_syntax_and_help(script: Path) -> None:
    assert script.stat().st_mode & 0o111
    subprocess.run(["bash", "-n", str(script)], check=True)
    result = subprocess.run(
        ["bash", str(script), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Usage:" in result.stdout


def test_lambda_release_requires_explicit_saved_plan_apply() -> None:
    source = Path("scripts/release-aws-lambdas.sh").read_text()
    assert "terraform -chdir=\"$environment_dir\" plan -out=\"$plan_name\"" in source
    assert "terraform -chdir=\"$environment_dir\" apply \"$plan_name\"" in source
    assert "-auto-approve" not in source
    assert "terraform_plan_sha256" in source
    assert 'select(.change.actions | index("delete"))' in source


@pytest.mark.parametrize(
    "generated_path",
    [
        "infra/environments/dev/image-overrides.auto.tfvars.json",
        "infra/environments/dev/release-manifest.json",
        "infra/environments/dev/tfplan",
    ],
)
def test_generated_release_files_are_ignored(generated_path: str) -> None:
    result = subprocess.run(
        ["git", "check-ignore", generated_path],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
