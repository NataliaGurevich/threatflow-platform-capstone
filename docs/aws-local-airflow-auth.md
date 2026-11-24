# Local Airflow authentication for S3 Bronze

This is a development-only bridge for Docker Compose. Airflow uses temporary credentials from
`aws login`; no access key is created or stored in `.env`. A production deployment should use a
workload identity such as an ECS task role instead.

## Identity boundary

Terraform optionally creates `threatflow-airflow-local` with no access keys and attaches only:

- the project-managed policy for `GetObject`/`PutObject` operations under the configured Bronze
  prefix;
- AWS-managed `SignInLocalDevelopmentAccess`, which permits the browser-based local login flow.

Terraform deliberately does not create a console password. Enable console access for this user
manually, require a password reset, and configure MFA. Never reuse the root login session.

## Host login cache

Use a dedicated cache directory outside the repository. It contains temporary credentials,
refresh material, and a private DPoP key, so it must be readable and writable only by its owner.
For this workspace on macOS, the intended values are:

```env
THREATFLOW_AWS_PROFILE=threatflow-airflow
THREATFLOW_AWS_CONFIG_FILE=/Users/natalia/.aws/config
THREATFLOW_AWS_LOGIN_CACHE_DIR=/Users/natalia/.aws/threatflow-airflow-login-cache
```

Create the directory with owner-only permissions before login. Run `aws login` with
`AWS_LOGIN_CACHE_DIRECTORY` pointing to that same directory and select the
`threatflow-airflow-local` console identity. The generated profile belongs in the normal AWS
config file; the credential cache remains isolated.

The SDK refreshes temporary credentials by writing updated tokens to the cache, so the cache
mount cannot be read-only. `docker-compose.aws.yml` exposes it only to `airflow-scheduler`, where
LocalExecutor runs task subprocesses. It does not expose credentials to the API server or DAG
processor.

## Verification and startup

Verify the named profile before starting Airflow:

```bash
aws sts get-caller-identity --profile threatflow-airflow
```

The ARN must identify `user/threatflow/threatflow-airflow-local`, never `root`.

Build and start the AWS-enabled Compose variant:

```bash
docker compose -f docker-compose.yml -f docker-compose.aws.yml build
docker compose -f docker-compose.yml -f docker-compose.aws.yml up -d
```

Verify the identity from the scheduler without printing credentials:

```bash
docker compose -f docker-compose.yml -f docker-compose.aws.yml exec airflow-scheduler \
  /opt/threatflow-venv/bin/python -c \
  'import boto3; print(boto3.client("sts").get_caller_identity()["Arn"])'
```

The ingestion runtime always writes accepted source data directly to S3; there is no dual-write
or replication switch. Do not unpause ingestion DAGs until the identity check and configured
Bronze/Silver bucket checks succeed. The login session eventually expires and requires an
interactive login; therefore this mechanism is suitable for a capstone demonstration, not
unattended production.
