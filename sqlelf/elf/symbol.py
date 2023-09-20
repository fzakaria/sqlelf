# Without this Python was complaining
from __future__ import annotations

from typing import Any, Iterator

import apsw
import apsw.ext
import lief

from sqlelf.elf.section import section_name as elf_section_name


def elf_symbols(binaries: list[lief.Binary]):
    def generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.name
            for symbol in symbols(binary):
                # The section index can be special numbers like 65521 or 65522
                # that refer to special sections so they can't be indexed
                section_name: str | None = next(
                    (
                        section.name
                        for shndx, section in enumerate(binary.sections)
                        if shndx == symbol.shndx
                    ),
                    None,
                )

                yield {
                    "path": binary_name,
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
                    "section": elf_section_name(section_name),
                    "size": symbol.size,
                    # TODO(fzakaria): Better understand why is it auxiliary?
                    # this returns versions like GLIBC_2.2.5
                    "version": symbol.symbol_version.symbol_version_auxiliary.name
                    if symbol.symbol_version
                    and symbol.symbol_version.symbol_version_auxiliary
                    else None,
                    "type": symbol.type.name,
                    "value": symbol.value,
                }

    return generator


def symbols(binary: lief.Binary) -> Iterator[lief.ELF.Symbol]:
    """Use heuristic to either get static symbols or dynamic symbol table

    The static symbol table is a superset of the dynamic symbol table.
    However it is often stripped from binaries as it's not needed beyond
    debugging.

    This method uses the simplest heuristic of checking for it's existence
    to return the static symbol table.

    A bad actor is free to strip arbitrarily from the static symbol table
    and it would affect this method.
    """
    static_symbols = binary.static_symbols  # pyright: ignore - missing from pyi
    if len(static_symbols) > 0:
        return static_symbols
    return binary.dynamic_symbols  # pyright: ignore - missing from pyi


def register(connection: apsw.Connection, binaries: list[lief.Binary]):
    generator = elf_symbols(binaries)
    # setup columns and access by providing an example of the first entry returned
    generator.columns, generator.column_access = apsw.ext.get_column_names(
        next(generator())
    )
    apsw.ext.make_virtual_module(connection, "raw_elf_symbols", generator)
    connection.execute(
        """
        CREATE TEMP TABLE elf_symbols
        AS SELECT * FROM raw_elf_symbols;
        CREATE INDEX elf_symbols_path_idx ON elf_symbols (path);
        CREATE INDEX elf_symbols_name_idx ON elf_symbols (name);
        """
    )
