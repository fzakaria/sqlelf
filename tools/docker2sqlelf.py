#!/usr/bin/env python3

import argparse
import atexit
import logging
import os
import shutil
import tempfile
from functools import reduce

import docker  # type: ignore

from sqlelf import elf, sql

LOG = logging.getLogger(__name__)


def docker2sqlelf(image_name: str, keep_temp_dir: bool, database_path: str) -> None:
    """Given a docker image, convert it to a sqlelf database.

    Args:
        image_name: The docker image name
        keep_temp_dir: Whether to keep the temporary directory
        database_path: The path to export the database to
    """
    client = docker.from_env()

    temp_dir = tempfile.mkdtemp()
    LOG.info(f"Created temporary directory at {temp_dir}")

    def cleanup() -> None:
        if not keep_temp_dir:
            LOG.info("Cleaning up...")
            shutil.rmtree(temp_dir)
            LOG.info(f"Removed temporary directory {temp_dir}")
        else:
            LOG.info(f"Keeping temporary directory {temp_dir}")

    atexit.register(cleanup)

    client.images.pull(image_name)
    container = client.containers.create(image_name)  # pyright: ignore
    LOG.info(f"Created container with ID {container.id}")

    export_path = f"{temp_dir}/container.tar"
    with open(export_path, "wb") as out_f:
        bits = container.export()  # pyright: ignore
        for chunk in bits:
            out_f.write(chunk)  # pyright: ignore
    LOG.info(f"Exported container's filesystem to {export_path}")

    shutil.unpack_archive(export_path, temp_dir)
    LOG.info(f"Extracted container's filesystem to {temp_dir}")

    container.remove()  # pyright: ignore
    LOG.info(f"Removed container {container.id}")

    filenames: list[str] = reduce(
        lambda a, b: a + b,
        map(
            lambda dir: (
                [
                    os.path.join(root, file)
                    for root, _, files in os.walk(dir)
                    for file in files
                ]
                if os.path.isdir(dir)
                else [dir]
            ),
            [temp_dir],
        ),
    )

    filenames = [f for f in filenames if os.path.isfile(f)]

    LOG.info("Creating sqlelf database")
    engine = sql.make_sql_engine(filenames, cache_flags=elf.CacheFlag.ALL())

    LOG.info("Dumping the sqlite database")
    engine.dump(database_path)

    LOG.info(f"Created database {database_path}")


if __name__ == "__main__":
    # Setup the logging config
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Convert docker image to sqlelf database."
    )
    parser.add_argument("image_name", help="Docker image name")
    parser.add_argument(
        "-k", "--keep", help="Keep temporary directory", action="store_true"
    )
    parser.add_argument(
        "-d",
        "--database",
        help="Database path to export to",
        default="database.sqlite",
    )
    args = parser.parse_args()

    docker2sqlelf(args.image_name, args.keep, args.database)
