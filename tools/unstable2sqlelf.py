#! /usr/bin/env python3
"""
Run this script like so:
python -m tools.unstable2sqlelf unstable-sqlite
"""
import argparse
import logging
import os
import re
import sqlite3

from tools.docker2sqlelf import docker2sqlelf

LOG = logging.getLogger(__name__)


def add_distribution_timestamp(database_path: str, docker_tag: str) -> None:
    """
    Add a distribution timestamp column to the ELF_HEADERS table in the given database.
    """
    LOG.info(f"Adding distribution timestamp to database: {database_path}")
    match = re.search(r"unstable-(\d+)", docker_tag)
    if match is None:
        raise ValueError(f"Invalid docker tag: {docker_tag}")
    timestamp = match.group(1)
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()
    cursor.execute("ALTER TABLE ELF_HEADERS ADD COLUMN DistributionTimestamp")
    cursor.execute("UPDATE ELF_HEADERS SET DistributionTimestamp = ?", (timestamp,))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    # Setup the logging config
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="Download all unstable Debian distributions as sqlite databases."
    )
    parser.add_argument(
        "output_directory",
        help="Output directory to store the files.",
        default="unstable-sqlite",
    )
    args = parser.parse_args()

    LOG.info(f"Creating output directory: {args.output_directory}")
    os.makedirs(args.output_directory, exist_ok=True)

    with open(
        os.path.join(os.path.dirname(__file__), "debian-unstable-tags.txt"), "r"
    ) as file:
        tags = file.read().splitlines()
        for tag in tags:
            LOG.info(f"Processing tag: {tag}")
            db_path = os.path.join(args.output_directory, f"debian-{tag}.sqlite")
            docker2sqlelf(f"debian:{tag}", False, db_path)
            add_distribution_timestamp(db_path, tag)
