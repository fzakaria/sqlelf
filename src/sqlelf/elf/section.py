from typing import Any, Iterator

import apsw
import apsw.ext
import lief


def elf_sections(binaries: list[lief.Binary]):
    def generator() -> Iterator[dict[str, Any]]:
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

    return generator


def section_name(name: str | None) -> str | None:
    if name == "":
        return "undefined"
    return name


def register(connection: apsw.Connection, binaries: list[lief.Binary]):
    generator = elf_sections(binaries)
    # setup columns and access by providing an example of the first entry returned
    generator.columns, generator.column_access = apsw.ext.get_column_names(next(generator()))
    apsw.ext.make_virtual_module(connection, "elf_sections", generator)
