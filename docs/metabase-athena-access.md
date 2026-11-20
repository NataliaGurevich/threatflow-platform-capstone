# Metabase access to Athena

## Views and daily refresh

Athena views are logical saved queries, not materialized datasets. They do not need a daily
refresh. Once the Gold job commits a new date and registers its Glue Catalog partitions, the next
query against a view sees that date automatically. Metabase result caching and schema-sync timing
are separate application settings.

## Terraform resources

The optional `athena_metabase` module creates:

- a private S3 bucket used only for Athena query results;
- a seven-day lifecycle expiration for result objects;
- an Athena SQL workgroup that enforces the result location, SSE-S3 encryption, expected bucket
  owner, CloudWatch metrics, engine version 3, and a per-query bytes-scanned cutoff;
- a dedicated IAM service-account user with no Terraform-managed access key;
- least-privilege access to the dedicated workgroup, `threatflow_gold` Glue metadata, read-only
  Gold objects, and read/write query-result objects.

The policy does not grant Glue writes, Gold S3 writes, or S3 deletes. Athena result cleanup is
performed by the bucket lifecycle rule.

Configure the development environment:

```hcl
create_athena_metabase_serving                 = true
athena_results_bucket_name                     = "threatflow-athena-results-dev-020502037761"
athena_results_retention_days                  = 7
athena_metabase_workgroup_name                 = "threatflow-metabase-dev"
athena_metabase_bytes_scanned_cutoff_per_query = 1000000000
athena_metabase_user_name                      = "threatflow-metabase-athena-dev"
```

Review and apply a saved plan:

```bash
terraform -chdir=infra/environments/dev plan -out=tfplan
terraform -chdir=infra/environments/dev show tfplan
terraform -chdir=infra/environments/dev apply tfplan
```

Do not create the IAM access key in Terraform because its secret would be retained in Terraform
state. After apply, create one key explicitly for the local Metabase connection:

```bash
aws iam create-access-key \
  --user-name threatflow-metabase-athena-dev
```

Treat the returned secret as a credential: enter it directly into Metabase, do not paste it into
chat or logs, and do not commit it to `.env` or Terraform files. Delete or rotate the key when it
is no longer needed. When Metabase moves to ECS, replace the IAM user with a task role and leave
the access-key fields blank so the Athena driver uses the default AWS credential chain.

Use these Metabase connection values:

```text
Region: eu-central-1
Workgroup: threatflow-metabase-dev
S3 staging directory: s3://threatflow-athena-results-dev-020502037761/metabase/
Catalog: AwsDataCatalog
Database: threatflow_gold
```

Athena charges are driven primarily by bytes scanned; S3 also charges for stored result objects
and requests. The partitioned Gold layout, summary-backed views, one-GB query cutoff, and result
lifecycle bound those costs. For operational auditability, keep CloudTrail management events and
consider S3 data events/server access logging if this moves beyond the capstone environment.
