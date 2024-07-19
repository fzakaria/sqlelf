from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Flag, auto
from typing import Any, Callable, Iterator, Sequence, Tuple, cast

import apsw
import apsw.ext
import capstone  # type: ignore
import lief

# ELF.pyi has no matching py file since it's a c extension
# pyright: reportMissingModuleSource=false
# https://github.com/microsoft/pyright/issues/5950
import lief.ELF

from sqlelf import lief_ext
from sqlelf._vendor.elftools.common.utils import bytes2str
from sqlelf._vendor.elftools.dwarf.descriptions import describe_form_class
from sqlelf._vendor.elftools.dwarf.die import DIE as DIE_t
from sqlelf._vendor.elftools.elf.elffile import ELFFile

LOG = logging.getLogger(__name__)


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
    RELOCATIONS = auto()
    STRINGS = auto()
    VERSION_REQUIREMENTS = auto()
    VERSION_DEFINITIONS = auto()
    DWARF_DIE = auto()
    DWARF_DIE_CALL_GRAPH = auto()
    DWARF_DEBUG_LINES = auto()

    @classmethod
    def from_string(cls: type[CacheFlag], str: str) -> CacheFlag:
        """Convert a string to a CacheFlag.

        This also specially handles 'ALL' which returns all the flags."""
        if str == "ALL":
            return cls.ALL()
        try:
            return cls[str]
        except KeyError:
            raise ValueError(f"{str} is not a valid CacheFlag")

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
            f"""CREATE TABLE {original_table_name}
            AS SELECT * FROM {table_name};"""
        )


def register_dynamic_entries_generator(
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the .dynamic section virtual table."""

    def dynamic_entries_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path
            for entry in binary.dynamic_entries:
                yield {
                    "path": binary_name,
                    "tag": entry.tag.__name__,
                    "value": entry.value,
                }

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
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF headers virtual table,"""

    def headers_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            yield {
                "path": binary.path,
                "type": binary.header.file_type.__name__,
                "machine": binary.header.machine_type.__name__,
                "version": binary.header.identity_version.__name__,
                "entry": binary.header.entrypoint,
                "is_pie": binary.is_pie,
            }

    generator = Generator.make_generator(
        ["path", "type", "machine", "version", "entry", "is_pie"],
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
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the instructions virtual table.

    This table includes dissasembled instructions from the executable sections"""

    def instructions_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path

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
                            "size": size,
                        }

    generator = Generator.make_generator(
        ["path", "section", "mnemonic", "address", "operands", "size"],
        instructions_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_instructions",
        CacheFlag.INSTRUCTIONS,
        cache_flags,
    )


def mode(binary: lief_ext.Binary) -> int:
    machine_type = binary.header.machine_type
    identity_class = binary.header.identity_class
    if machine_type == lief.ELF.ARCH.RISCV:
        if identity_class == lief.ELF.ELF_CLASS.CLASS32:
            return cast(int, capstone.CS_MODE_RISCV32)
    if machine_type == lief.ELF.ARCH.RISCV:
        if identity_class == lief.ELF.ELF_CLASS.CLASS64:
            return cast(int, capstone.CS_MODE_RISCV64)
    if machine_type == lief.ELF.ARCH.x86_64:
        if identity_class == lief.ELF.ELF_CLASS.CLASS64:
            return cast(int, capstone.CS_MODE_64)
    raise RuntimeError(f"Unknown mode for {binary.path}")


def arch(binary: lief_ext.Binary) -> int:
    if binary.header.machine_type == lief.ELF.ARCH.x86_64:
        return cast(int, capstone.CS_ARCH_X86)
    elif binary.header.machine_type == lief.ELF.ARCH.RISCV:
        return cast(int, capstone.CS_ARCH_RISCV)
    raise RuntimeError(f"Unknown machine type for {binary.path}")


def register_sections_generator(
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF sections virtual table."""

    def sections_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path
            for section in binary.sections:
                try:
                    yield {
                        "path": binary_name,
                        "name": section.name,
                        "offset": section.offset,
                        "size": section.size,
                        "type": section.type.__name__,
                        "content": bytes(section.content),
                    }
                except RuntimeError:
                    # TODO(fzakaria): LIEF is failing to parse some section types:
                    # https://github.com/lief-project/LIEF/issues/1031
                    # Just skip them for now
                    LOG.warning(
                        "Failed to parse section: %s (%s)", section.name, binary_name
                    )
                    pass

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


def register_strings_generator(
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
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
            binary_name = binary.path
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
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF symbols virtual table."""

    def symbols_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path
            for symbol in symbols(binary):
                # The section index can be special numbers like 65521 or 65522
                # that refer to special sections so they can't be indexed
                section_name: str | None = next(
                    (
                        # technically name can be bytes, for now avoid this possibility
                        # https://github.com/lief-project/LIEF/issues/965#issuecomment-1718702335
                        cast(str, section.name)
                        for shndx, section in enumerate(binary.sections)
                        if shndx == symbol.shndx
                    ),
                    None,
                )
                if section_name is None or section_name == "":
                    section_name = lief.ELF.SYMBOL_SECTION_INDEX.from_value(
                        symbol.shndx
                    ).__name__

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
                    "section": section_name,
                    "size": symbol.size,
                    # TODO(fzakaria): Better understand why is it auxiliary?
                    # this returns versions like GLIBC_2.2.5
                    "version": (
                        symbol.symbol_version.symbol_version_auxiliary.name
                        if symbol.symbol_version
                        and symbol.symbol_version.symbol_version_auxiliary
                        else None
                    ),
                    "type": symbol.type.__name__,
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


def register_relocations_generator(
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF relocations virtual table."""

    def relocations_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path
            for relocation in binary.relocations:
                yield {
                    "path": binary_name,
                    "addend": relocation.addend,
                    "info": relocation.info,
                    # Relocations are either of type Elf64_Rela or Elf64_Rel
                    # the difference being whether addend is present in the struct
                    # https://refspecs.linuxbase.org/elf/gabi4+/ch4.reloc.html
                    "is_rela": relocation.is_rela,
                    "purpose": relocation.purpose.__name__,
                    "section": (
                        relocation.section.name if relocation.section else None
                    ),
                    "symbol": relocation.symbol.name if relocation.symbol else None,
                    "symbol_table": (
                        relocation.symbol_table.name
                        if relocation.symbol_table
                        else None
                    ),
                    "type": relocation_type(
                        binary.header.machine_type, relocation.type
                    ),
                }

    generator = Generator.make_generator(
        [
            "path",
            "addend",
            "info",
            "is_rela",
            "purpose",
            "section",
            "symbol",
            "symbol_table",
            "type",
        ],
        relocations_generator,
    )

    register_generator(
        connection,
        generator,
        "elf_relocations",
        CacheFlag.RELOCATIONS,
        cache_flags,
    )


def relocation_type(arch: lief.ELF.ARCH, type: int) -> str:
    """Return the relocation type as a string for a given arch."""
    if arch == lief.ELF.ARCH.x86_64:
        return lief.ELF.RELOCATION_X86_64.from_value(type).__name__
    raise RuntimeError(f"Unknown relocation type for {arch}")


def register_version_requirements(
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF version requirements virtual table.

    This should match the values found in .gnu.version_r section.
    It's not 100% clear whether this table is needed since it's in the symbol table."""

    def version_requirements_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path
            symbol_version_req = binary.symbols_version_requirement
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
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the ELF version requirements virtual table.

    This should match the values found in .gnu.version_d section.
    It's not 100% clear whether this table is needed since it's in the symbol table"""

    def version_definitions_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path
            symbol_version_def = binary.symbols_version_definition
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


def register_dwarf_dies(
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the DWARF DIE (Debugging Information Entry) virtual table."""

    def determine_high_low_pc(DIE: DIE_t) -> Tuple[int | None, int | None]:
        """Determine the high_pc.

        The high_pc can be either an address or an offset from the low_pc.
        DWARF v4 in section 2.17 describes how to interpret the
        DW_AT_high_pc attribute based on the class of its form.
        For class 'address' it's taken as an absolute address
        (similarly to DW_AT_low_pc); for class 'constant', it's
        an offset from DW_AT_low_pc.
        https://github.com/eliben/pyelftools/blob/5d31cad41e7c5701db024f228255276a48cd65d1/examples/dwarf_decode_address.py#L53C1-L68C33
        """
        low_pc_attr = DIE.attributes.get("DW_AT_low_pc", None)
        if not low_pc_attr:
            return (None, None)
        low_pc = low_pc_attr.value
        high_pc_attr = DIE.attributes.get("DW_AT_high_pc", None)
        # TODO(fzakaria): understand why high can be not be present if low exists
        # seems to be possible though...
        if not high_pc_attr:
            return (low_pc, None)
        high_pc_attr_class = describe_form_class(high_pc_attr.form)
        high_pc = None
        if high_pc_attr_class == "address":
            high_pc = high_pc_attr.value
        elif high_pc_attr_class == "constant":
            high_pc = low_pc + high_pc_attr.value
        else:
            raise RuntimeError("Unknown attribute class: %s" % high_pc_attr_class)
        return (low_pc, high_pc)

    def dwarf_dies_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path
            # A bit annoying but we must re-open the file
            # since we are using a different library here
            with open(binary_name, "rb") as f:
                elf_file = ELFFile(f)
                if not elf_file.has_dwarf_info():
                    continue
                # get_dwarf_info returns a DWARFInfo context object, which is the
                # starting point for all DWARF-based processing in pyelftools.
                dwarf_info = elf_file.get_dwarf_info()
                for CU in dwarf_info.iter_CUs():
                    for DIE in CU.iter_DIEs():
                        # iter_DIEs can return null DIES which are terminators
                        if DIE is None:
                            continue
                        die_name = DIE.attributes.get("DW_AT_name", None)
                        low_pc, high_pc = determine_high_low_pc(DIE)
                        yield {
                            "path": binary_name,
                            "tag": DIE.tag,
                            "name": bytes2str(die_name.value) if die_name else None,
                            "low_pc": low_pc,
                            "high_pc": high_pc,
                            # This is also the primary key of the DIE
                            "offset": DIE.offset,
                            "size": DIE.size,
                            "cu_offset": CU.cu_offset,
                        }

    generator = Generator.make_generator(
        ["path", "tag", "name", "low_pc", "high_pc", "offset", "size", "cu_offset"],
        dwarf_dies_generator,
    )

    register_generator(
        connection,
        generator,
        "dwarf_dies",
        CacheFlag.DWARF_DIE,
        cache_flags,
    )


def register_dwarf_dies_graph(
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the DWARF DIE (Debugging Information Entry) graph virtual table."""

    def dwarf_dies_graph_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path
            # A bit annoying but we must re-open the file
            # since we are using a different library here
            with open(binary_name, "rb") as f:
                elf_file = ELFFile(f)
                if not elf_file.has_dwarf_info():
                    continue
                # get_dwarf_info returns a DWARFInfo context object, which is the
                # starting point for all DWARF-based processing in pyelftools.
                dwarf_info = elf_file.get_dwarf_info()
                for CU in dwarf_info.iter_CUs():
                    for DIE in CU.iter_DIEs():
                        # iter_DIEs can return null DIES which are terminators
                        if DIE is None:
                            continue
                        for DIE_child in DIE.iter_children():
                            yield {
                                "path": binary_name,
                                "parent_offset": DIE.offset,
                                "child_offset": DIE_child.offset,
                            }

    generator = Generator.make_generator(
        ["path", "parent_offset", "child_offset"],
        dwarf_dies_graph_generator,
    )

    register_generator(
        connection,
        generator,
        "dwarf_dies_graph",
        CacheFlag.DWARF_DIE_CALL_GRAPH,
        cache_flags,
    )


def register_dwarf_debug_lines(
    binaries: list[lief_ext.Binary], connection: apsw.Connection, cache_flags: CacheFlag
) -> None:
    """Create the DWARF debug_lines virtual table."""

    def dwarf_debug_lines_generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.path
            # A bit annoying but we must re-open the file
            # since we are using a different library here
            with open(binary_name, "rb") as f:
                elf_file = ELFFile(f)
                if not elf_file.has_dwarf_info():
                    continue
                # get_dwarf_info returns a DWARFInfo context object, which is the
                # starting point for all DWARF-based processing in pyelftools.
                dwarf_info = elf_file.get_dwarf_info()
                for CU in dwarf_info.iter_CUs():
                    debug_lines = dwarf_info.line_program_for_CU(CU)
                    if debug_lines is None:
                        continue
                    file_entries = debug_lines.header["file_entry"]
                    directory_entries = debug_lines.header["include_directory"]
                    # The line program, when decoded, returns a list of line program
                    # entries. Each entry contains a state, which we'll use to build
                    # a reverse mapping of filename -> #entries.
                    lp_entries = debug_lines.get_entries()
                    for lpe in lp_entries:
                        # We skip LPEs that don't have an associated file.
                        # This can happen if instructions in the compiled binary
                        # don't correspond directly to any original source file.
                        if not lpe.state or lpe.state.file == 0:
                            continue

                        # File and directory indices are 1-indexed.
                        file_entry = file_entries[lpe.state.file - 1]
                        dir_index = file_entry["dir_index"]
                        directory = (
                            directory_entries[dir_index - 1]
                            if dir_index > 0
                            else "".encode()
                        )

                        filename = os.path.join(directory, file_entry.name)

                        yield {
                            "path": binary_name,
                            "filename": bytes2str(filename),
                            "address": lpe.state.address,
                            "line": lpe.state.line,
                            "column": lpe.state.column,
                            "cu_offset": CU.cu_offset,
                        }

    generator = Generator.make_generator(
        ["path", "filename", "address", "line", "column", "cu_offset"],
        dwarf_debug_lines_generator,
    )

    register_generator(
        connection,
        generator,
        "dwarf_debug_lines",
        CacheFlag.DWARF_DEBUG_LINES,
        cache_flags,
    )

    if CacheFlag.DWARF_DEBUG_LINES in cache_flags:
        connection.execute(
            """CREATE INDEX dwarf_debug_lines_cu_offset_idx
                ON dwarf_debug_lines (cu_offset);"""
        )


def symbols(binary: lief_ext.Binary) -> Sequence[lief.ELF.Symbol]:
    """Use heuristic to either get static symbols or dynamic symbol table

    Always return the dynamic symbol table first and then the static symbols
    if it exists. From the static symbols, exclude any symbol that is also present
    in the dynamic symbol table so that it is not counted twice.

    We prefer symbols from the dynamic symbol table because the static symbol table
    will not include version information.
    """
    static_symbols: Sequence[lief.ELF.Symbol] = binary.static_symbols  # type: ignore
    dynamic_symbols = list(binary.dynamic_symbols)
    dynamic_symbol_names = set(map(lambda s: s.name, dynamic_symbols))
    all_symbols = dynamic_symbols + [
        s for s in static_symbols if s.name not in dynamic_symbol_names
    ]
    return all_symbols


def register_virtual_tables(
    connection: apsw.Connection,
    binaries: list[lief_ext.Binary],
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
        register_relocations_generator,
        register_version_requirements,
        register_version_definitions,
        register_dwarf_dies,
        register_dwarf_dies_graph,
        register_dwarf_debug_lines,
    ]
    for register_function in register_table_functions:
        register_function(binaries, connection, cache_flags)
