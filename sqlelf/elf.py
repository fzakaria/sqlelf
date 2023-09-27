from __future__ import annotations

from dataclasses import dataclass
from enum import Flag, auto
from typing import Any, Callable, Iterator, Sequence, cast

import apsw
import apsw.ext
import capstone  # type: ignore
import lief


@dataclass
class Generator:
    """A generator for the virtual table SQLite module.

    This class is needed because apsw wants to assign columns and
    column_access to the generator function itself."""

    columns: Sequence[str]
    column_access: apsw.ext.VTColumnAccess
    callable: Callable[[], Iterator[dict[str, Any]]]

    def __call__(self) -> Iterator[dict[str, Any]]:
        """Call the generator should return an iterator of dictionaries.

        The dictionaries should have keys that match the column names."""
        return self.callable()

    @staticmethod
    def make_generator(
        columns: list[str], generator: Callable[[], Iterator[dict[str, Any]]]
    ) -> Generator:
        """Create a generator from a callable that returns
        an iterator of dictionaries."""
        return Generator(columns, apsw.ext.VTColumnAccess.By_Name, generator)


class CacheFlag(Flag):
    NONE = 0
    DYNAMIC_ENTRIES = auto()
    HEADERS = auto()
    INSTRUCTIONS = auto()
    SECTIONS = auto()
    SYMBOLS = auto()
    STRINGS = auto()
    VERSION_REQUIREMENTS = auto()
    VERSION_DEFINITIONS = auto()

    @classmethod
    def ALL(cls: type[CacheFlag]) -> CacheFlag:
        retval = cls.NONE
        for member in cls.__members__.values():
            retval |= member
        return retval


def register_generator(
    connection: apsw.Connection,
    generator: Generator,
    table_name: str,
    generator_flag: CacheFlag,
    cache_flags: CacheFlag,
) -> None:
    """Register a virtual table generator.

    This method does a bit of duplicate work which checks if we need to cache
    the given generator.

    If so we rename the table with a prefix 'raw' and then create a temp table"""
    original_table_name = table_name
    if generator_flag in cache_flags:
        table_name = f"raw_{table_name}"

    apsw.ext.make_virtual_module(connection, table_name, generator)

    if generator_flag in cache_flags:
        connection.execute(
            f"""CREATE TEMP TABLE {original_table_name}
            AS SELECT * FROM {table_name};"""
        )


def register_dynamic_entries_generator(
    binaries: list[lief.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the .dynamic section virtual table."""

    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.name
            for entry in binary.dynamic_entries:  # type: ignore
                yield {"path": binary_name, "tag": entry.tag.name, "value": entry.value}

    generator = Generator.make_generator(
        ["path", "tag", "value"],
        dynamic_entries_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_dynamic_entries",
        CacheFlag.DYNAMIC_ENTRIES,
        cache_flags,
    )


def register_headers_generator(
    binaries: list[lief.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF headers virtual table,"""

    def headers_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            yield {
                "path": binary.name,
                "type": binary.header.file_type.name,
                "machine": binary.header.machine_type.name,
                "version": binary.header.identity_version.name,
                "entry": binary.header.entrypoint,
            }

    generator = Generator.make_generator(
        ["path", "type", "machine", "version", "entry"],
        headers_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_headers",
        CacheFlag.HEADERS,
        cache_flags,
    )


def register_instructions_generator(
    binaries: list[lief.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the instructions virtual table.

    This table includes dissasembled instructions from the executable sections"""

    def instructions_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.name

            for section in binary.sections:
                if section.has(lief.ELF.SECTION_FLAGS.EXECINSTR):
                    data = bytes(section.content)
                    md = capstone.Cs(arch(binary), mode(binary))
                    # keep in mind that producing details costs more memory,
                    # complicates the internal operations and slows down
                    # the engine a bit, so only do that if needed.
                    md.detail = False

                    # super important that these accessors are pulled out
                    # of the tight loop as they can be costly
                    section_name = section.name
                    for address, size, mnemonic, op_str in md.disasm_lite(
                        data, section.virtual_address
                    ):
                        yield {
                            "path": binary_name,
                            "section": section_name,
                            "mnemonic": mnemonic,
                            "address": address,
                            "operands": op_str,
                        }

    generator = Generator.make_generator(
        ["path", "section", "mnemonic", "address", "operands"],
        instructions_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_instructions",
        CacheFlag.INSTRUCTIONS,
        cache_flags,
    )


def mode(binary: lief.Binary) -> int:
    if binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64:
        return cast(int, capstone.CS_MODE_64)
    raise RuntimeError(f"Unknown mode for {binary.name}")


def arch(binary: lief.Binary) -> int:
    if binary.header.machine_type == lief.ELF.ARCH.x86_64:
        return cast(int, capstone.CS_ARCH_X86)
    raise RuntimeError(f"Unknown machine type for {binary.name}")


def register_sections_generator(
    binaries: list[lief.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF sections virtual table."""

    def sections_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.name
            for section in binary.sections:
                yield {
                    "path": binary_name,
                    "name": section.name,
                    "offset": section.offset,
                    "size": section.size,
                    "type": section.type.name,
                    "content": bytes(section.content),
                }

    generator = Generator.make_generator(
        ["path", "name", "offset", "size", "type", "content"],
        sections_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_sections",
        CacheFlag.SECTIONS,
        cache_flags,
    )


def coerce_section_name(name: str | None) -> str | None:
    """Return a section name or undefined if the name is empty."""
    if name == "":
        return "undefined"
    return name


def register_strings_generator(
    binaries: list[lief.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF strings virtual table.

    This goes through all string tables in the ELF binary and splits them on null bytes.
    """

    def strings_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            strtabs = [
                section
                for section in binary.sections
                if section.type == lief.ELF.SECTION_TYPES.STRTAB
            ]
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.name
            for strtab in strtabs:
                # The first byte is always the null byte in the STRTAB
                # Python also treats the final null in the string by creating
                # an empty item so we chop it off.
                # https://stackoverflow.com/a/18970869
                strtab_name = strtab.name
                for offset, string in split_with_index(
                    str(strtab.content[1:-1], "utf-8"), "\x00"
                ):
                    yield {
                        "path": binary_name,
                        "section": strtab_name,
                        "value": string,
                        # we add one from the offset since we removed the
                        # null byte at the start of the STRTAB
                        "offset": offset + 1,
                    }

    generator = Generator.make_generator(
        ["path", "section", "value", "offset"],
        strings_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_strings",
        CacheFlag.STRINGS,
        cache_flags,
    )

    if CacheFlag.STRINGS in cache_flags:
        connection.execute(
            """CREATE INDEX elf_strings_offset_idx ON elf_strings (offset);"""
        )


def split_with_index(str: str, delimiter: str) -> list[tuple[int, str]]:
    """Split a string with the delimiter and return the index
    of the start of the split."""
    start = 0
    result = []
    for i, c in enumerate(str):
        if c == delimiter:
            result.append((start, str[start:i]))
            start = i + 1
    result.append((start, str[start:]))
    return result


def register_symbols_generator(
    binaries: list[lief.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF symbols virtual table."""

    def symbols_generator() -> Iterator[dict[str, Any]]:
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
                    "section": coerce_section_name(section_name),
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

    generator = Generator.make_generator(
        [
            "path",
            "name",
            "demangled_name",
            "imported",
            "exported",
            "section",
            "size",
            "version",
            "type",
            "value",
        ],
        symbols_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_symbols",
        CacheFlag.SYMBOLS,
        cache_flags,
    )

    if CacheFlag.SYMBOLS in cache_flags:
        connection.execute(
            """CREATE INDEX elf_symbols_path_idx ON elf_symbols (path);
              CREATE INDEX elf_symbols_name_idx ON elf_symbols (name);"""
        )


def register_version_requirements(
    binaries: list[lief.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF version requirements virtual table.

    This should match the values found in .gnu.version_r section.
    It's not 100% clear whether this table is needed since it's in the symbol table."""

    def version_requirements_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.name
            symbol_version_req = binary.symbols_version_requirement  # type: ignore
            for version_requirement in symbol_version_req:
                file = version_requirement.name
                for aux_requirement in version_requirement.get_auxiliary_symbols():
                    yield {
                        "path": binary_name,
                        "file": file,
                        "name": aux_requirement.name,
                    }

    generator = Generator.make_generator(
        ["path", "file", "name"],
        version_requirements_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_version_requirements",
        CacheFlag.VERSION_REQUIREMENTS,
        cache_flags,
    )


def register_version_definitions(
    binaries: list[lief.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF version requirements virtual table.

    This should match the values found in .gnu.version_d section.
    It's not 100% clear whether this table is needed since it's in the symbol table"""

    def version_definitions_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.name
            symbol_version_def = binary.symbols_version_definition  # type: ignore
            for version_definition in symbol_version_def:
                flags = version_definition.flags
                for aux_definition in version_definition.auxiliary_symbols:
                    yield {
                        "path": binary_name,
                        "name": aux_definition.name,
                        "flags": flags,
                    }

    generator = Generator.make_generator(
        ["path", "name", "flags"],
        version_definitions_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_version_definitions",
        CacheFlag.VERSION_DEFINITIONS,
        cache_flags,
    )


def symbols(binary: lief.Binary) -> Sequence[lief.ELF.Symbol]:
    """Use heuristic to either get static symbols or dynamic symbol table

    The static symbol table is a superset of the dynamic symbol table.
    However it is often stripped from binaries as it's not needed beyond
    debugging.

    This method uses the simplest heuristic of checking for its existence
    to return the static symbol table.

    A bad actor is free to strip arbitrarily from the static symbol table
    and it would affect this method.
    """
    static_symbols: Sequence[lief.ELF.Symbol] = binary.static_symbols  # type: ignore
    if len(static_symbols) > 0:
        return static_symbols
    return binary.dynamic_symbols  # type: ignore


def register_virtual_tables(
    connection: apsw.Connection,
    binaries: list[lief.Binary],
    cache_flags: CacheFlag = CacheFlag.INSTRUCTIONS | CacheFlag.SYMBOLS,
) -> None:
    """Register the virtual table modules.

    You can make the SQL engine more speedy by only specifying the
    Generators (virtual tables) that you care about via the flags argument.

    Args:
        connection: the connection to register the virtual tables on
        binaries: the list of binaries to analyze
        flags: the bitwise flags which controls which virtual table to enable"""
    register_table_functions = [
        register_dynamic_entries_generator,
        register_headers_generator,
        register_instructions_generator,
        register_sections_generator,
        register_strings_generator,
        register_symbols_generator,
        register_version_requirements,
        register_version_definitions,
    ]
    for register_function in register_table_functions:
        register_function(binaries, connection, cache_flags)
