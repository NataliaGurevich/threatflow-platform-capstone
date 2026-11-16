"""Reconcile committed NVD Bronze windows with immutable Silver commits."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote_plus

import boto3
from botocore.exceptions import ClientError

from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.nvd_window import parse_nvd_window_manifest


@dataclass(frozen=True)
class NvdReconciliationItem:
    bronze_key: str
    bronze_version_id: str
    window_sha256: str
    silver_manifest_key: str
    status: str


def reconcile_nvd_silver(
    *,
    bronze_bucket: str,
    silver_bucket: str,
    bronze_prefix: str = "bronze",
    silver_prefix: str = "silver",
    queue_url: str | None = None,
    apply: bool = False,
    s3_client: Any,
    sqs_client: Any | None = None,
) -> list[NvdReconciliationItem]:
    """Find missing Silver commits and optionally enqueue exact S3 notifications."""
    if apply and (not queue_url or sqs_client is None):
        raise ValueError("apply requires queue_url and an SQS client")
    paginator = s3_client.get_paginator("list_object_versions")
    candidates = []
    for response in paginator.paginate(
        Bucket=bronze_bucket, Prefix=f"{bronze_prefix.strip('/')}/source=nvd/"
    ):
        candidates.extend(
            item
            for item in response.get("Versions", [])
            if item.get("Key", "").endswith(".window.json") and item.get("IsLatest")
        )
    results = []
    for candidate in sorted(candidates, key=lambda item: item["Key"]):
        response = s3_client.get_object(
            Bucket=bronze_bucket,
            Key=candidate["Key"],
            VersionId=candidate["VersionId"],
        )
        body = response["Body"]
        try:
            content = body.read()
        finally:
            body.close()
        digest = calculate_sha256(content)
        manifest = parse_nvd_window_manifest(content)
        timestamp = manifest.requested_end.strftime("%Y-%m-%dT%H-%M-%SZ")
        silver_key = (
            f"{silver_prefix.strip('/')}/nvd_cve_windows/mode={manifest.mode}/"
            f"window_end={timestamp}/window_id={digest}/_manifest.json"
        )
        try:
            s3_client.head_object(Bucket=silver_bucket, Key=silver_key)
            status = "committed"
        except ClientError as exc:
            if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 404:
                raise
            status = "missing"
        if apply and status == "missing":
            event = _s3_event(
                bronze_bucket,
                candidate["Key"],
                candidate["VersionId"],
                candidate["Size"],
            )
            sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(event))
            status = "enqueued"
        results.append(
            NvdReconciliationItem(
                candidate["Key"], candidate["VersionId"], digest, silver_key, status
            )
        )
    return results


def _s3_event(bucket: str, key: str, version_id: str, size: int) -> dict[str, Any]:
    return {
        "Records": [
            {
                "eventSource": "aws:s3",
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {
                        "key": quote_plus(key),
                        "size": size,
                        "versionId": version_id,
                    },
                },
            }
        ]
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--bronze-bucket", required=True)
    parser.add_argument("--silver-bucket", required=True)
    parser.add_argument("--queue-url")
    parser.add_argument("--region")
    args = parser.parse_args()
    session = boto3.Session(region_name=args.region)
    s3 = session.client("s3")
    sqs = session.client("sqs") if args.apply else None
    results = reconcile_nvd_silver(
        bronze_bucket=args.bronze_bucket,
        silver_bucket=args.silver_bucket,
        queue_url=args.queue_url,
        apply=args.apply,
        s3_client=s3,
        sqs_client=sqs,
    )
    print(json.dumps([item.__dict__ for item in results], indent=2, sort_keys=True))
    if any(item.status == "missing" for item in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
