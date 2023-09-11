from typing import Any, Iterator

import apsw
import apsw.ext

from sqlelf.elf.binary import Binary


def elf_headers(binaries: list[Binary]):
    def generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            yield {
                "path": binary.path,
                "type": binary.header.file_type.__name__,
                "machine": binary.header.machine_type.__name__,
                "version": binary.header.identity_version.__name__,
                "entry": binary.header.entrypoint,
            }

    return generator


def register(connection: apsw.Connection, binaries: list[Binary]):
    generator = elf_headers(binaries)
    # setup columns and access by providing an example of the first entry returned
    generator.columns, generator.column_access = apsw.ext.get_column_names(
        next(generator())
    )
    apsw.ext.make_virtual_module(connection, "elf_headers", generator)
