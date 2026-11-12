# ThreatFlow AWS infrastructure

Terraform manages the small AWS extension to the local ThreatFlow capstone. The first module
defines a protected Amazon S3 General Purpose bucket for immutable Bronze artifacts and a
least-privilege IAM policy. The development root can also create and attach that policy to the
dedicated local Airflow identity.

No Terraform command in this repository should receive long-lived credentials. Use a temporary
AWS CLI/SSO session when a real plan is eventually required. Never commit `terraform.tfvars`,
state files, credentials, or plan files.

## Layout

```text
infra/
├── modules/bronze_storage/       reusable S3 and IAM module
└── environments/dev/             development root module
```

The module configures:

- Block Public Access on all four controls;
- disabled ACLs through `BucketOwnerEnforced`;
- S3 Versioning;
- default SSE-S3 encryption;
- a bucket policy denying non-TLS requests;
- `prevent_destroy` and `force_destroy = false`;
- expiry of noncurrent versions after 90 days by default;
- cleanup of incomplete multipart uploads after seven days;
- object read/write access only under `bronze/*`, without object deletion.

Current Bronze objects do not expire. This preserves the governance requirement that exact Raw
artifacts remain available for audit and replay. The noncurrent-version rule limits accidental
overwrite history; content-addressed application keys should not normally create such versions.

## Static verification without AWS access

```sh
terraform -chdir=infra/environments/dev fmt -check -recursive
terraform -chdir=infra/environments/dev init -backend=false
terraform -chdir=infra/environments/dev validate

terraform -chdir=infra/modules/bronze_storage init -backend=false
terraform -chdir=infra/modules/bronze_storage test
```

The tests use a mocked AWS provider. They create no AWS resources and require no credentials.

## Development deployment and changes

Copy the example without committing the result:

```sh
cp infra/environments/dev/terraform.tfvars.example infra/environments/dev/terraform.tfvars
```

After authenticating with short-lived AWS credentials, review a saved plan:

```sh
terraform -chdir=infra/environments/dev plan -out=tfplan
terraform -chdir=infra/environments/dev show tfplan
```

Apply only after reviewing the exact account, region, bucket name, IAM policy, and estimated
cost impact. `prevent_destroy` intentionally blocks ordinary destruction of the stateful bucket.

## Cost and observability

Amazon S3 charges include stored bytes, requests, data transfer, and retained noncurrent object
versions. SSE-S3 avoids customer-managed KMS key and request charges. Lifecycle operations and
monitoring can add charges; confirm the selected Region on the official S3 pricing page before
deployment.

The first slice does not create a log bucket or trail. Before treating the environment as more
than a capstone development deployment, add scoped CloudTrail S3 data events, encrypted log
destinations, CloudWatch alarms/metrics, and access logging where its additional bucket and
request cost is justified.

References:

- [Amazon S3 security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Amazon S3 pricing](https://aws.amazon.com/s3/pricing/)
- [Terraform provider mocking](https://developer.hashicorp.com/terraform/language/tests/mocking)
