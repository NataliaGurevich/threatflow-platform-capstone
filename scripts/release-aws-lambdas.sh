#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
project_root="$(dirname "$script_dir")"
cd "$project_root"

environment_dir="infra/environments/dev"
overrides_file="${environment_dir}/image-overrides.auto.tfvars.json"
manifest_file="${environment_dir}/release-manifest.json"
plan_name="tfplan"
plan_file="${environment_dir}/${plan_name}"

expected_account="${THREATFLOW_AWS_ACCOUNT_ID:-020502037761}"
aws_region="${AWS_REGION:-eu-central-1}"
aws_profile="${AWS_PROFILE:-threatflow-deploy}"
registry="${expected_account}.dkr.ecr.${aws_region}.amazonaws.com"
cisa_repository="threatflow-cisa-silver-dev"
epss_repository="threatflow/epss-silver"
nvd_repository="threatflow-nvd-silver-dev"
cisa_function="threatflow-cisa-silver-dev"
epss_function="threatflow-epss-silver-dev"
nvd_function="threatflow-nvd-silver-dev"

usage() {
  cat <<'EOF'
Usage: scripts/release-aws-lambdas.sh plan|apply|verify [--skip-tests]

  plan    Test, build, smoke-test, push immutable NVD/CISA/EPSS images, write local
          auto-tfvars, and create a saved Terraform plan. This changes ECR only.
  apply   Verify the saved plan checksum, apply that exact plan, and verify AWS.
  verify  Compare Terraform image overrides with deployed Lambda resolved digests.

Environment overrides:
  AWS_PROFILE                 default: threatflow-deploy
  AWS_REGION                  default: eu-central-1
  THREATFLOW_AWS_ACCOUNT_ID   default: 020502037761
EOF
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

action="$1"
shift
skip_tests=false
while (($# > 0)); do
  case "$1" in
    --skip-tests) skip_tests=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$action" in
  plan|apply|verify) ;;
  -h|--help) usage; exit 0 ;;
  *) echo "error: action must be plan, apply, or verify" >&2; usage >&2; exit 2 ;;
esac

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

for command_name in aws docker git jq shasum terraform; do
  require_command "$command_name"
done

aws_cli=(aws --profile "$aws_profile" --region "$aws_region")

verify_identity() {
  local actual_account caller_arn
  actual_account="$("${aws_cli[@]}" sts get-caller-identity --query Account --output text)"
  caller_arn="$("${aws_cli[@]}" sts get-caller-identity --query Arn --output text)"
  if [[ "$actual_account" != "$expected_account" ]]; then
    echo "error: authenticated to AWS account ${actual_account}, expected ${expected_account}" >&2
    exit 1
  fi
  echo "AWS identity: ${caller_arn}"
  echo "AWS region:   ${aws_region}"
}

resolved_image_uri() {
  "${aws_cli[@]}" lambda get-function \
    --function-name "$1" \
    --query 'Code.ResolvedImageUri' \
    --output text
}

verify_deployment() {
  if [[ ! -f "$overrides_file" ]]; then
    echo "error: missing ${overrides_file}; run plan first" >&2
    exit 1
  fi

  local expected_cisa expected_epss expected_nvd actual_cisa actual_epss actual_nvd
  expected_cisa="$(jq -er '.cisa_silver_lambda_image_uri' "$overrides_file")"
  expected_epss="$(jq -er '.epss_silver_lambda_image_uri' "$overrides_file")"
  expected_nvd="$(jq -er '.nvd_silver_lambda_image_uri' "$overrides_file")"
  actual_cisa="$(resolved_image_uri "$cisa_function")"
  actual_epss="$(resolved_image_uri "$epss_function")"
  actual_nvd="$(resolved_image_uri "$nvd_function")"

  [[ "$actual_cisa" == "$expected_cisa" ]] || {
    echo "error: CISA Lambda digest mismatch" >&2
    echo "expected: ${expected_cisa}" >&2
    echo "actual:   ${actual_cisa}" >&2
    exit 1
  }
  [[ "$actual_epss" == "$expected_epss" ]] || {
    echo "error: EPSS Lambda digest mismatch" >&2
    echo "expected: ${expected_epss}" >&2
    echo "actual:   ${actual_epss}" >&2
    exit 1
  }
  [[ "$actual_nvd" == "$expected_nvd" ]] || {
    echo "error: NVD Lambda digest mismatch" >&2
    echo "expected: ${expected_nvd}" >&2
    echo "actual:   ${actual_nvd}" >&2
    exit 1
  }

  for function_name in "$cisa_function" "$epss_function" "$nvd_function"; do
    status="$("${aws_cli[@]}" lambda get-function \
      --function-name "$function_name" \
      --query '[Configuration.State,Configuration.LastUpdateStatus]' \
      --output text)"
    [[ "$status" == $'Active\tSuccessful' ]] || {
      echo "error: ${function_name} is not Active/Successful: ${status}" >&2
      exit 1
    }
    mapping_state="$("${aws_cli[@]}" lambda list-event-source-mappings \
      --function-name "$function_name" \
      --query 'EventSourceMappings[0].State' \
      --output text)"
    [[ "$mapping_state" == "Enabled" ]] || {
      echo "error: ${function_name} event-source mapping is ${mapping_state}" >&2
      exit 1
    }
  done

  dashboard_name="$("${aws_cli[@]}" cloudwatch get-dashboard \
    --dashboard-name threatflow-dev-bronze-to-silver \
    --query DashboardName \
    --output text)"
  [[ "$dashboard_name" == "threatflow-dev-bronze-to-silver" ]] || {
    echo "error: pipeline dashboard is missing" >&2
    exit 1
  }

  echo "PASS: deployed Lambda digests, mappings, and dashboard match the release"
}

verify_identity

if [[ "$action" == "verify" ]]; then
  verify_deployment
  exit 0
fi

if [[ "$action" == "apply" ]]; then
  [[ -f "$plan_file" ]] || { echo "error: missing saved plan ${plan_file}" >&2; exit 1; }
  [[ -f "$manifest_file" ]] || { echo "error: missing ${manifest_file}" >&2; exit 1; }
  [[ -f "$overrides_file" ]] || { echo "error: missing ${overrides_file}" >&2; exit 1; }
  expected_plan_sha="$(jq -er '.terraform_plan_sha256' "$manifest_file")"
  actual_plan_sha="$(shasum -a 256 "$plan_file" | awk '{print $1}')"
  [[ "$actual_plan_sha" == "$expected_plan_sha" ]] || {
    echo "error: saved Terraform plan checksum does not match release manifest" >&2
    exit 1
  }
  [[ "$(jq -er '.cisa_silver_lambda_image_uri' "$overrides_file")" == "$(jq -er '.cisa_image_uri' "$manifest_file")" ]] || {
    echo "error: CISA image override changed after the saved plan was created" >&2
    exit 1
  }
  [[ "$(jq -er '.epss_silver_lambda_image_uri' "$overrides_file")" == "$(jq -er '.epss_image_uri' "$manifest_file")" ]] || {
    echo "error: EPSS image override changed after the saved plan was created" >&2
    exit 1
  }
  [[ "$(jq -er '.nvd_silver_lambda_image_uri' "$overrides_file")" == "$(jq -er '.nvd_image_uri' "$manifest_file")" ]] || {
    echo "error: NVD image override changed after the saved plan was created" >&2
    exit 1
  }
  terraform -chdir="$environment_dir" apply "$plan_name"
  verify_deployment
  exit 0
fi

if [[ "$skip_tests" == false ]]; then
  echo "==> Running Ruff"
  .venv/bin/python -m ruff check .
  echo "==> Running Python tests"
  .venv/bin/python -m pytest -q
  echo "==> Running Terraform module test"
  terraform -chdir=infra/modules/pipeline_observability test
fi

commit_sha="$(git rev-parse --short=12 HEAD)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
image_tag="pipeline-${commit_sha}-${timestamp}"
if [[ -n "$(git status --short)" ]]; then
  image_tag="${image_tag}-dirty"
fi

echo "==> Logging Docker into ECR"
"${aws_cli[@]}" ecr get-login-password \
  | docker login --username AWS --password-stdin "$registry"

build_and_push() {
  local component="$1"
  local repository="$2"
  local local_image="threatflow-${component}-silver:${image_tag}"
  local remote_image="${registry}/${repository}:${image_tag}"

  echo "==> Building ${component} Lambda image"
  docker buildx build \
    --platform linux/arm64 \
    --provenance=false \
    --load \
    -f "lambda/${component}_silver/Dockerfile" \
    -t "$local_image" \
    .

  docker run --rm \
    --platform linux/arm64 \
    --entrypoint python \
    "$local_image" \
    -c "from threatflow.transformation.${component}_silver_lambda import lambda_handler; print(lambda_handler.__name__)"

  docker tag "$local_image" "$remote_image"
  docker push "$remote_image"

  "${aws_cli[@]}" ecr describe-images \
    --repository-name "$repository" \
    --image-ids "imageTag=${image_tag}" \
    --query 'imageDetails[0].imageDigest' \
    --output text
}

cisa_digest="$(build_and_push cisa "$cisa_repository" | tee /dev/stderr | tail -n 1)"
epss_digest="$(build_and_push epss "$epss_repository" | tee /dev/stderr | tail -n 1)"
nvd_digest="$(build_and_push nvd "$nvd_repository" | tee /dev/stderr | tail -n 1)"

digest_pattern='^sha256:[0-9a-f]{64}$'
[[ "$cisa_digest" =~ $digest_pattern ]] || { echo "error: invalid CISA digest: ${cisa_digest}" >&2; exit 1; }
[[ "$epss_digest" =~ $digest_pattern ]] || { echo "error: invalid EPSS digest: ${epss_digest}" >&2; exit 1; }
[[ "$nvd_digest" =~ $digest_pattern ]] || { echo "error: invalid NVD digest: ${nvd_digest}" >&2; exit 1; }

cisa_image_uri="${registry}/${cisa_repository}@${cisa_digest}"
epss_image_uri="${registry}/${epss_repository}@${epss_digest}"
nvd_image_uri="${registry}/${nvd_repository}@${nvd_digest}"

temporary_overrides="${overrides_file}.tmp"
temporary_manifest="${manifest_file}.tmp"
trap 'rm -f "$temporary_overrides" "$temporary_manifest"' EXIT HUP INT TERM

jq -n \
  --arg cisa "$cisa_image_uri" \
  --arg epss "$epss_image_uri" \
  --arg nvd "$nvd_image_uri" \
  '{cisa_silver_lambda_image_uri:$cisa,epss_silver_lambda_image_uri:$epss,nvd_silver_lambda_image_uri:$nvd}' \
  >"$temporary_overrides"
mv "$temporary_overrides" "$overrides_file"

echo "==> Initializing and validating Terraform"
terraform -chdir="$environment_dir" init
terraform -chdir="$environment_dir" validate
terraform -chdir="$environment_dir" plan -out="$plan_name"

destructive_changes="$(
  terraform -chdir="$environment_dir" show -json "$plan_name" \
    | jq '[.resource_changes[]? | select(.change.actions | index("delete"))] | length'
)"
if [[ "$destructive_changes" != "0" ]]; then
  echo "error: Terraform plan contains ${destructive_changes} delete or replacement action(s):" >&2
  terraform -chdir="$environment_dir" show -json "$plan_name" \
    | jq -r '.resource_changes[]? | select(.change.actions | index("delete")) | "  \(.address): \(.change.actions | join(","))"' >&2
  echo "Refusing to create an applicable release manifest." >&2
  exit 1
fi

plan_sha="$(shasum -a 256 "$plan_file" | awk '{print $1}')"
dirty=false
[[ -n "$(git status --short)" ]] && dirty=true
jq -n \
  --arg created_at "$timestamp" \
  --arg git_commit "$(git rev-parse HEAD)" \
  --arg image_tag "$image_tag" \
  --arg cisa_image_uri "$cisa_image_uri" \
  --arg epss_image_uri "$epss_image_uri" \
  --arg nvd_image_uri "$nvd_image_uri" \
  --arg terraform_plan_sha256 "$plan_sha" \
  --argjson working_tree_dirty "$dirty" \
  '{created_at:$created_at,git_commit:$git_commit,working_tree_dirty:$working_tree_dirty,image_tag:$image_tag,cisa_image_uri:$cisa_image_uri,epss_image_uri:$epss_image_uri,nvd_image_uri:$nvd_image_uri,terraform_plan_sha256:$terraform_plan_sha256}' \
  >"$temporary_manifest"
mv "$temporary_manifest" "$manifest_file"

echo
echo "Saved Terraform plan: ${plan_file}"
echo "Release manifest:     ${manifest_file}"
echo "CISA image:           ${cisa_image_uri}"
echo "EPSS image:           ${epss_image_uri}"
echo "NVD image:            ${nvd_image_uri}"
echo "Review with: terraform -chdir=${environment_dir} show ${plan_name}"
echo "Apply with:  scripts/release-aws-lambdas.sh apply"
