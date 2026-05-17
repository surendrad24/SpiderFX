#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compare two SpiderFoot scans and print net-new / removed findings."""

import argparse
import json
import sqlite3
import sys
from collections import Counter


def load_scan_events(db_path, scan_guid):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT type, data
        FROM tbl_scan_results
        WHERE scan_instance_id = ?
          AND false_positive = 0
        """,
        (scan_guid,),
    )
    rows = cur.fetchall()

    cur.execute(
        """
        SELECT guid, name, seed_target, started, ended, status
        FROM tbl_scan_instance
        WHERE guid = ?
        """,
        (scan_guid,),
    )
    scan_meta = cur.fetchone()

    conn.close()

    if scan_meta is None:
        raise ValueError(f"Scan GUID not found: {scan_guid}")

    items = set((r[0], r[1]) for r in rows)
    type_counts = Counter(r[0] for r in rows)

    meta = {
        "guid": scan_meta[0],
        "name": scan_meta[1],
        "seed_target": scan_meta[2],
        "started": scan_meta[3],
        "ended": scan_meta[4],
        "status": scan_meta[5],
    }

    return meta, items, type_counts


def summarize_by_type(pairs):
    c = Counter(p[0] for p in pairs)
    return dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))


def main():
    p = argparse.ArgumentParser(description="Diff two SpiderFoot scans")
    p.add_argument("--db", required=True, help="Path to spiderfoot.db")
    p.add_argument("--old", required=True, help="Older scan GUID")
    p.add_argument("--new", required=True, help="Newer scan GUID")
    p.add_argument("--limit", type=int, default=50, help="Sample item limit for added/removed output")
    p.add_argument("--json", action="store_true", help="Output JSON")
    args = p.parse_args()

    try:
        old_meta, old_items, old_counts = load_scan_events(args.db, args.old)
        new_meta, new_items, new_counts = load_scan_events(args.db, args.new)
    except Exception as e:
        print(f"ERROR: {e}")
        return 1

    added = sorted(new_items - old_items)
    removed = sorted(old_items - new_items)

    result = {
        "old_scan": old_meta,
        "new_scan": new_meta,
        "old_event_total": len(old_items),
        "new_event_total": len(new_items),
        "added_total": len(added),
        "removed_total": len(removed),
        "added_by_type": summarize_by_type(added),
        "removed_by_type": summarize_by_type(removed),
        "new_scan_type_counts": dict(sorted(new_counts.items())),
        "old_scan_type_counts": dict(sorted(old_counts.items())),
        "added_sample": [{"type": a[0], "data": a[1]} for a in added[: args.limit]],
        "removed_sample": [{"type": r[0], "data": r[1]} for r in removed[: args.limit]],
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Old scan: {old_meta['guid']} ({old_meta['name']}) target={old_meta['seed_target']}")
        print(f"New scan: {new_meta['guid']} ({new_meta['name']}) target={new_meta['seed_target']}")
        print(f"Old events: {len(old_items)}")
        print(f"New events: {len(new_items)}")
        print(f"Added: {len(added)}")
        print(f"Removed: {len(removed)}")
        print("\nAdded by type:")
        for k, v in result["added_by_type"].items():
            print(f"  {k}: {v}")
        print("\nRemoved by type:")
        for k, v in result["removed_by_type"].items():
            print(f"  {k}: {v}")

        if result["added_sample"]:
            print("\nAdded sample:")
            for item in result["added_sample"]:
                print(f"  + [{item['type']}] {item['data']}")

        if result["removed_sample"]:
            print("\nRemoved sample:")
            for item in result["removed_sample"]:
                print(f"  - [{item['type']}] {item['data']}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
