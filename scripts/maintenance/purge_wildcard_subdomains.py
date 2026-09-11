"""
Find and delete wildcard-DNS artifact targets.

Parking providers and resellers answer every label under a parked zone, so
subdomain discovery used to turn their wildcard answers into (thousands of)
targets. A target is an artifact when its current DNS answer is
indistinguishable from what a random label under its parent zone returns
(see yads/core/wildcard_dns.py). Real subdomains with their own records are
kept, and so are names that currently don't resolve.

Dry run by default -- take a DB backup before running with --apply.

Usage:
    python scripts/maintenance/purge_wildcard_subdomains.py --tenant-id 2 [--out list.txt] [--apply]
"""
import argparse
import collections
import os
import sys

# Add project root to sys.path to allow importing 'yads'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

import dns.resolver
import tldextract
from sqlmodel import Session, select

from yads.api.routers.targets import _perform_bulk_delete_from_db
from yads.core.wildcard_dns import WildcardCache, find_wildcard_artifacts
from yads.database import engine
from yads.models import Target

DELETE_BATCH = 500


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tenant-id", type=int, required=True)
    parser.add_argument("--workers", type=int, default=20, help="parallel DNS lookups")
    parser.add_argument("--out", help="write the artifact domains to this file")
    parser.add_argument("--apply", action="store_true", help="actually delete (default: dry run)")
    args = parser.parse_args()

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    with Session(engine) as session:
        rows = session.exec(select(Target.id, Target.domain).where(Target.tenant_id == args.tenant_id)).all()
        ids = {domain: target_id for target_id, domain in rows}
        print(f"Checking {len(ids)} targets of tenant {args.tenant_id} for wildcard-DNS artifacts...")

        artifacts = sorted(find_wildcard_artifacts(ids, WildcardCache(resolver), workers=args.workers))
        by_domain = collections.Counter(tldextract.extract(d).registered_domain or d for d in artifacts)
        print(f"Found {len(artifacts)} artifact targets under {len(by_domain)} registrable domain(s):")
        for domain, count in by_domain.most_common():
            print(f"  {domain:40s} {count}")

        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write("\n".join(artifacts) + "\n")
            print(f"Wrote list to {args.out}")

        if not args.apply:
            print("Dry run -- nothing deleted. Re-run with --apply after taking a DB backup.")
            return

        target_ids = [ids[d] for d in artifacts]
        for i in range(0, len(target_ids), DELETE_BATCH):
            _perform_bulk_delete_from_db(session, target_ids[i:i + DELETE_BATCH])
            session.commit()
            print(f"  deleted {min(i + DELETE_BATCH, len(target_ids))}/{len(target_ids)}")
        print(f"Deleted {len(target_ids)} artifact targets.")


if __name__ == "__main__":
    main()
