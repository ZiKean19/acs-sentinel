"""
backfill_gsi.py — one-off migration for the log-stream "by-time" GSI.

The new dashboard reads logs through a GSI whose partition key is the
constant attribute gsi_pk = "LOG". New rows get the attribute at write time
(Detection + Dashboard Lambdas both set it); rows written BEFORE this change
lack it and are therefore invisible to the index. This script scans the
table once and stamps the attribute onto every row that is missing it.

Run once from your machine (uses your local AWS credentials):

    python backfill_gsi.py                       # table: log-stream
    python backfill_gsi.py --table log-stream --region ap-southeast-1

Safe to re-run: rows that already carry gsi_pk are skipped.
Cost: one scan + one small update per legacy row — cents at FYP scale.
"""

import argparse
import boto3

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--table", default="log-stream")
    ap.add_argument("--region", default="ap-southeast-1")
    args = ap.parse_args()

    dynamo = boto3.client("dynamodb", region_name=args.region)

    scanned = updated = 0
    kwargs = {"TableName": args.table}
    while True:
        resp = dynamo.scan(**kwargs)
        for item in resp.get("Items", []):
            scanned += 1
            if "gsi_pk" in item:
                continue
            log_id = item.get("log_id", {}).get("S")
            if not log_id:
                continue
            dynamo.update_item(
                TableName=args.table,
                Key={"log_id": {"S": log_id}},
                UpdateExpression="SET gsi_pk = :p",
                ExpressionAttributeValues={":p": {"S": "LOG"}},
            )
            updated += 1
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    print(f"Scanned {scanned} rows, backfilled {updated}.")

if __name__ == "__main__":
    main()
