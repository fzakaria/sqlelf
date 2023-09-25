from __future__ import annotations

from dataclasses import dataclass
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


def make_dynamic_entries_generator(binaries: list[lief.Binary]) -> Generator:
    """Create the .dynamic section virtual table."""

    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.name
            for entry in binary.dynamic_entries:  # type: ignore
                yield {"path": binary_name, "tag": entry.tag.name, "value": entry.value}

    return Generator.make_generator(
        ["path", "tag", "value"],
        dynamic_entries_generator,
    )


def make_headers_generator(binaries: list[lief.Binary]) -> Generator:
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

    return Generator.make_generator(
        ["path", "type", "machine", "version", "entry"],
        headers_generator,
    )


def make_instructions_generator(binaries: list[lief.Binary]) -> Generator:
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

    return Generator.make_generator(
        ["path", "section", "mnemonic", "address", "operands"],
        instructions_generator,
    )


def mode(binary: lief.Binary) -> int:
    if binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64:
        return cast(int, capstone.CS_MODE_64)
    raise RuntimeError(f"Unknown mode for {binary.name}")


def arch(binary: lief.Binary) -> int:
    if binary.header.machine_type == lief.ELF.ARCH.x86_64:
        return cast(int, capstone.CS_ARCH_X86)
    raise RuntimeError(f"Unknown machine type for {binary.name}")


def make_sections_generator(binaries: list[lief.Binary]) -> Generator:
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

    return Generator.make_generator(
        ["path", "name", "offset", "size", "type", "content"],
        sections_generator,
    )


def coerce_section_name(name: str | None) -> str | None:
    """Return a section name or undefined if the name is empty."""
    if name == "":
        return "undefined"
    return name


def make_strings_generator(binaries: list[lief.Binary]) -> Generator:
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
                for string in str(strtab.content[1:-1], "utf-8").split("\x00"):
                    yield {"path": binary_name, "section": strtab.name, "value": string}

    return Generator.make_generator(
        ["path", "section", "value"],
        strings_generator,
    )


def make_symbols_generator(binaries: list[lief.Binary]) -> Generator:
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

    return Generator.make_generator(
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


def make_version_requirements(binaries: list[lief.Binary]) -> Generator:
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

    return Generator.make_generator(
        ["path", "file", "name"], version_requirements_generator
    )


def make_version_definitions(binaries: list[lief.Binary]) -> Generator:
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

    return Generator.make_generator(
        ["path", "name", "flags"], version_definitions_generator
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
    connection: apsw.Connection, binaries: list[lief.Binary]
) -> None:
    """Register the virtual table modules."""
    factory_and_names = [
        (make_dynamic_entries_generator, "elf_dynamic_entries"),
        (make_headers_generator, "elf_headers"),
        (make_instructions_generator, "raw_elf_instructions"),
        (make_sections_generator, "elf_sections"),
        (make_strings_generator, "elf_strings"),
        (make_symbols_generator, "raw_elf_symbols"),
        (make_version_requirements, "elf_version_requirements"),
        (make_version_definitions, "elf_version_definitions"),
    ]
    for factory, name in factory_and_names:
        generator = factory(binaries)
        apsw.ext.make_virtual_module(connection, name, generator)
    connection.execute(
        """
        CREATE TEMP TABLE elf_instructions
        AS SELECT * FROM raw_elf_instructions;

        CREATE TEMP TABLE elf_symbols
        AS SELECT * FROM raw_elf_symbols;
        CREATE INDEX elf_symbols_path_idx ON elf_symbols (path);
        CREATE INDEX elf_symbols_name_idx ON elf_symbols (name);
        """
    )
