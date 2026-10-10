import argparse
import csv
import json
import sys
from pathlib import Path
from dotenv import load_dotenv
from .core import enrich, build_report, save


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Defensive CTI IOC enrichment and reporting")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ioc", help="Single indicator")
    group.add_argument("--file", help="CSV with ioc,type columns or one IOC,type per line")
    parser.add_argument("--type", choices=["ip", "domain", "url", "hash"], default="ip")
    parser.add_argument("--out", default="reports")
    args = parser.parse_args()
    items = [(args.ioc, args.type)] if args.ioc else []
    if args.file:
        with open(args.file, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if not row or row[0].strip().startswith("#") or row[0].strip().lower() == "ioc":
                    continue
                items.append((row[0].strip(), row[1].strip() if len(row) > 1 else "ip"))
    results = []
    for ioc, kind in items:
        try:
            results.append(enrich(ioc, kind))
        except (ValueError, KeyError) as exc:
            print(f"Skipping invalid indicator {ioc!r}: {exc}", file=sys.stderr)
    if not results:
        parser.error("No valid indicators to process")
    report = build_report(results)
    files = save(report, args.out)
    print(json.dumps(report["counts"], indent=2))
    print("Saved:", *files, sep="\n - ")


if __name__ == "__main__":
    main()
