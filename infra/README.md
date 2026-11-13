# ThreatFlow AWS infrastructure

Terraform manages the small AWS extension to the local ThreatFlow capstone. Separate modules
define protected Amazon S3 General Purpose buckets for immutable Bronze artifacts and derived
Silver datasets. A third module defines the Standard queue and DLQ that will decouple S3 Bronze
events from the future EPSS transformation Lambda. A fourth module creates the private ECR
repository for its container image. A fifth module creates the image-based ARM64 Lambda, its
dedicated execution role, and a bounded CloudWatch log group. The Bronze module also exposes a
least-privilege ingestion policy that the development root can attach to the dedicated local
Airflow identity.

No Terraform command in this repository should receive long-lived credentials. Use a temporary
AWS CLI/SSO session when a real plan is eventually required. Never commit `terraform.tfvars`,
state files, credentials, or plan files.

## Layout

```text
infra/
├── modules/bronze_storage/       reusable S3 and ingestion IAM module
├── modules/silver_storage/       reusable S3 Silver module
├── modules/epss_silver_queue/    reusable SQS event queue and DLQ module
├── modules/epss_silver_image/    private ECR image repository module
├── modules/epss_silver_lambda/   Lambda, execution role, and log group module
└── environments/dev/             development root module
```

Both storage modules configure:

- Block Public Access on all four controls;
- disabled ACLs through `BucketOwnerEnforced`;
- S3 Versioning;
- default SSE-S3 encryption;
- a bucket policy denying non-TLS requests;
- `prevent_destroy` and `force_destroy = false`;
- cleanup of incomplete multipart uploads after seven days;
- no public access.

Bronze retains noncurrent versions for 90 days by default and exposes ingestion object read/write
access only under `bronze/*`, without object deletion. The Lambda role is narrower: it can only
read exact object versions under `bronze/source=epss/*`. Silver retains noncurrent versions for 30
days by default and publishes committed datasets under `silver/*`; the Lambda can only read and
write `silver/epss_scores/*`. It receives no bucket listing, object deletion, KMS, or PostgreSQL access.
It additionally receives `ReceiveMessage`, `DeleteMessage`, and `GetQueueAttributes` only for the
dedicated EPSS event queue; no queue wildcard is used.

Current Bronze objects do not expire. This preserves the governance requirement that exact Raw
artifacts remain available for audit and replay. The noncurrent-version rule limits accidental
overwrite history; content-addressed application keys should not normally create such versions.
Current Silver objects also do not expire because they are the analytical history. Silver remains
rebuildable from Bronze, so its superseded versions have a shorter default recovery window.

The EPSS event queue is Standard rather than FIFO because S3 notifications can be duplicated and
unordered, while the application handler is idempotent. It uses SQS-managed encryption, 20-second
long polling, four-day message retention, and a 30-minute visibility timeout. The visibility
timeout is six times the planned five-minute Lambda timeout. After five failed receives, SQS moves
the message to a dedicated DLQ retained for 14 days. The DLQ accepts redrive only from this source
queue. Both queue policies deny non-TLS access; the source policy permits only `sqs:SendMessage`
from the configured Bronze bucket in the current AWS account.

The SQS-to-Lambda event-source mapping is enabled with one message per invocation, partial batch
failure reporting, no batching delay, and maximum concurrency of two. Lambda long-polls the queue
and deletes a message only after the handler reports success; repeated deliveries remain safe
because the Silver writer is idempotent. This slice deliberately creates no S3 bucket notification,
so new Bronze objects do not yet enqueue messages automatically. The filtered S3 notification and
a DLQ alarm belong to later slices.

The EPSS image repository uses immutable tags, AES256 encryption, basic scan-on-push, and refuses
forced deletion. Its lifecycle expires only images that have remained untagged for seven days;
tagged releases are not automatically deleted because the Lambda references an immutable digest.
The repository module does not build or push an image. Terraform deliberately accepts the exact
`IMAGE_URI` as an input and rejects tag-only references such as `:latest`.

The function uses the ARM64 architecture, 2048 MiB memory, a five-minute timeout, and the shared
unreserved account concurrency pool. This is compatible with development accounts whose regional
concurrency quota is too small to allocate function-level reservations. The SQS event-source
mapping caps this data flow at two concurrent invocations without reserving account capacity. The
30-minute queue visibility timeout is validated as at least six times the function timeout.
CloudWatch logs use JSON format and expire after 14 days by default; Terraform creates the group
before the function, so its role does not need `logs:CreateLogGroup`.

## Static verification without AWS access

```sh
terraform -chdir=infra/environments/dev fmt -check -recursive
terraform -chdir=infra/environments/dev init -backend=false
terraform -chdir=infra/environments/dev validate

terraform -chdir=infra/modules/bronze_storage init -backend=false
terraform -chdir=infra/modules/bronze_storage test

terraform -chdir=infra/modules/silver_storage init -backend=false
terraform -chdir=infra/modules/silver_storage test

terraform -chdir=infra/modules/epss_silver_queue init -backend=false
terraform -chdir=infra/modules/epss_silver_queue test

terraform -chdir=infra/modules/epss_silver_image init -backend=false
terraform -chdir=infra/modules/epss_silver_image test

terraform -chdir=infra/modules/epss_silver_lambda init -backend=false
terraform -chdir=infra/modules/epss_silver_lambda test
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

Apply only after reviewing the exact account, region, both bucket names, both queue names, ECR
repository name, IAM policies, and estimated cost impact. `prevent_destroy` intentionally blocks
ordinary destruction of both stateful buckets. After apply, set `THREATFLOW_S3_SILVER_BUCKET` to
the `silver_bucket_name` Terraform output; do not commit the resulting `.env`.

After Terraform creates ECR, build one ARM64 image and use a unique immutable tag such as a release
plus Git commit. Replace placeholders with the Terraform output and chosen tag:

```sh
docker buildx build \
  --platform linux/arm64 \
  --provenance=false \
  --load \
  -f lambda/epss_silver/Dockerfile \
  -t threatflow-epss-silver:<image-tag> \
  .

aws ecr get-login-password --region eu-central-1 \
  | docker login --username AWS --password-stdin 020502037761.dkr.ecr.eu-central-1.amazonaws.com

docker tag \
  threatflow-epss-silver:<image-tag> \
  <repository-url>:<image-tag>
docker push <repository-url>:<image-tag>

aws ecr describe-images \
  --repository-name threatflow/epss-silver \
  --image-ids imageTag=<image-tag> \
  --region eu-central-1 \
  --query 'imageDetails[0].imageDigest' \
  --output text

aws ecr describe-image-scan-findings \
  --repository-name threatflow/epss-silver \
  --image-id imageDigest=<image-digest> \
  --region eu-central-1 \
  --query '{status:imageScanStatus.status,findings:imageScanFindings.findingSeverityCounts}'
```

Set `epss_silver_lambda_image_uri` in the ignored `terraform.tfvars` to
`<repository-url>@<image-digest>`, not to a tag. Do not commit ECR login material or Docker
credentials.

## Manual Lambda invocation

After applying the reviewed function plan, copy the checked-in fixture and replace its Bronze
bucket, URL-encoded key, exact `versionId`, and byte `size` with values from one accepted EPSS
object. `list-object-versions` supplies all four source values without downloading the feed:

```sh
aws s3api list-object-versions \
  --bucket threatflow-bronze-dev-capstone \
  --prefix bronze/source=epss/ \
  --region eu-central-1 \
  --query 'Versions[?IsLatest] | [0].{Key:Key,VersionId:VersionId,Size:Size}'

cp lambda/epss_silver/events/s3_object_created.manual.json.example \
  /tmp/threatflow-epss-silver-event.json
```

Invoke only after the copied JSON contains the matching values. AWS CLI v2 requires
`--cli-binary-format raw-in-base64-out` for the JSON payload:

```sh
aws lambda invoke \
  --function-name threatflow-epss-silver-dev \
  --region eu-central-1 \
  --cli-binary-format raw-in-base64-out \
  --payload fileb:///tmp/threatflow-epss-silver-event.json \
  /tmp/threatflow-epss-silver-response.json

python -m json.tool /tmp/threatflow-epss-silver-response.json
```

A successful first invocation reports one created partition; replaying the same fixture reports
the same partition with `created: false`. Verify that the Parquet file and `_manifest.json` exist
under the reported `silver/epss_scores/score_date=.../` prefix. No notification or queue is needed
for this manual test.

## Manual SQS-to-Lambda test

After applying the event-source mapping, send the same direct S3 event JSON as one queue message.
The caller needs `sqs:SendMessage`; the Lambda role itself intentionally does not have that action:

```sh
aws sqs send-message \
  --queue-url https://sqs.eu-central-1.amazonaws.com/020502037761/threatflow-epss-bronze-events-dev \
  --message-body file:///tmp/threatflow-epss-silver-event.json \
  --region eu-central-1
```

Lambda wraps that body in the normal SQS invocation event, processes the exact Bronze object
version, and deletes the message after success. Verify the queue returns to zero visible and
in-flight messages and inspect the structured function logs:

```sh
aws sqs get-queue-attributes \
  --queue-url https://sqs.eu-central-1.amazonaws.com/020502037761/threatflow-epss-bronze-events-dev \
  --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible \
  --region eu-central-1

aws logs tail /aws/lambda/threatflow-epss-silver-dev \
  --since 10m \
  --region eu-central-1
```

## Cost and observability

Amazon S3 charges include stored bytes, requests, data transfer, and retained noncurrent object
versions; a second bucket does not introduce a fixed bucket charge. SSE-S3 avoids
customer-managed KMS key and request charges. Lifecycle operations and monitoring can add
charges; confirm the selected Region on the official S3 pricing page before deployment.

SQS Standard queues have no fixed provisioning charge; usage is billed by API requests and data
transfer where applicable. Long polling reduces empty receive requests, and SQS-managed
encryption avoids customer-managed KMS request charges. DLQ retention preserves failure evidence
but increases the time during which failed messages remain stored. Confirm current regional
pricing before apply.

ECR charges for stored image bytes and applicable data transfer. Basic scanning has no separate
scan charge; enhanced continuous scanning would add Amazon Inspector cost and is intentionally not
enabled account-wide for this development capstone. Lambda charges accrue only for requests and
execution duration. The SQS event-source mapping limits parallelism without reserving the
account's small shared concurrency quota. CloudWatch Logs charges depend on ingestion and
retained bytes, with retention bounded to 14 days by default.

The storage slices do not create a log bucket or trail. Before treating the environment as more
than a capstone development deployment, add scoped CloudTrail S3 data events, encrypted log
destinations, CloudWatch alarms/metrics, and access logging where its additional bucket and
request cost is justified.

References:

- [Amazon S3 security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [Amazon S3 pricing](https://aws.amazon.com/s3/pricing/)
- [Amazon SQS pricing](https://aws.amazon.com/sqs/pricing/)
- [Amazon SQS dead-letter queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)
- [AWS Lambda Python container images](https://docs.aws.amazon.com/lambda/latest/dg/python-image.html)
- [AWS Lambda execution roles](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)
- [Amazon ECR tag immutability](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html)
- [Terraform provider mocking](https://developer.hashicorp.com/terraform/language/tests/mocking)
