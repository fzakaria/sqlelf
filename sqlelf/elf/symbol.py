# Without this Python was complaining
from __future__ import annotations

from typing import Any, Iterator

import apsw
import apsw.ext
import lief


def elf_symbols(binaries: list[lief.Binary]):
    def generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            for symbol in binary.symbols:
                yield {
                    "path": binary.name,
                    "name": symbol.name,
                    "demangled_name": symbol.demangled_name,
                    # If this is empty, then it is a dynamic symbol
                    "section": binary.sections[symbol.shndx].name,
                    "size": symbol.size,
                }

    return generator


def register(connection: apsw.Connection, binaries: list[lief.Binary]):
    generator = elf_symbols(binaries)
    # setup columns and access by providing an example of the first entry returned
    generator.columns, generator.column_access = apsw.ext.get_column_names(
        next(generator())
    )
    apsw.ext.make_virtual_module(connection, "elf_symbols", generator)
