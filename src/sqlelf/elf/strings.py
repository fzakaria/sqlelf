from typing import Any, Iterator

import apsw
import apsw.ext
import lief


def elf_strings(binaries: list[lief.Binary]):
    def generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            strtabs = [section for section in binary.sections if section.type == lief.ELF.SECTION_TYPES.STRTAB]
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

    return generator


def register(connection: apsw.Connection, binaries: list[lief.Binary]):
    generator = elf_strings(binaries)
    # setup columns and access by providing an example of the first entry returned
    generator.columns, generator.column_access = apsw.ext.get_column_names(next(generator()))
    apsw.ext.make_virtual_module(connection, "elf_strings", generator)
