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


def docker2sqelf(image_name: str, keep_temp_dir: bool = False) -> str:
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

    container = client.containers.create(image_name)
    LOG.info(f"Created container with ID {container.id}")

    export_path = f"{temp_dir}/container.tar"
    with open(export_path, "wb") as out_f:
        bits = container.export()  # pyright: ignore
        for chunk in bits:
            out_f.write(chunk)
    LOG.info(f"Exported container's filesystem to {export_path}")

    shutil.unpack_archive(export_path, temp_dir)
    LOG.info(f"Extracted container's filesystem to {temp_dir}")

    container.remove()  # pyright: ignore
    LOG.info(f"Removed container {container.id}")

    modified_image_name = image_name.replace(":", "-")

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
    database_filename = f"{modified_image_name}.sqlite"
    engine.dump(database_filename)

    LOG.info(f"Created database {database_filename}")
    return database_filename


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert docker image to sqlelf database."
    )
    parser.add_argument("image_name", help="Docker image name")
    parser.add_argument(
        "-k", "--keep", help="Keep temporary directory", action="store_true"
    )
    args = parser.parse_args()

    docker2sqelf(args.image_name, args.keep)
