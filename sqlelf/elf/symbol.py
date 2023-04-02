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
                    # A bit of detailed explanation here to explain these values.
                    # A symbol may point to the SHN_UNDEF section which is a good it's
                    # an "imported symbol" -- meaning it needs to be linked in.
                    # If the section is != SH_UNDEF then it is "exported" as it's
                    # logic resides within this shared object file.
                    # refs:
                    # https://github.com/lief-project/LIEF/blob/0875ee2467d5ae6628d8bf3f4f0b82ca5854c401/src/ELF/Symbol.cpp#L90
                    # https://stackoverflow.com/questions/12666253/elf-imports-and-exports
                    # https://www.m4b.io/elf/export/binary/analysis/2015/05/25/what-is-an-elf-export.html
                    "imported": symbol.imported,
                    "exported": symbol.exported,
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
