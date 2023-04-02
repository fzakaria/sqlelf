# Without this Python was complaining
from __future__ import annotations

from typing import Any, Iterator

import apsw
import apsw.ext
import lief


def elf_headers(binaries: list[lief.Binary]):
    def generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            yield {
                "path": binary.name,
                "type": binary.header.file_type.name,
                "machine": binary.header.machine_type.name,
                "version": binary.header.identity_version.name,
                "entry": binary.header.entrypoint,
            }

    return generator


def register(connection: apsw.Connection, binaries: list[lief.Binary]):
    generator = elf_headers(binaries)
    # setup columns and access by providing an example of the first entry returned
    generator.columns, generator.column_access = apsw.ext.get_column_names(
        next(generator())
    )
    apsw.ext.make_virtual_module(connection, "elf_headers", generator)
