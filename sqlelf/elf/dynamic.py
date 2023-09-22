# Without this Python was complaining
from __future__ import annotations

from typing import Any, Iterator

import apsw
import apsw.ext
import lief


# This is effectively the .dynamic section but it is elevated as a table here
# since it is widely used and can benefit from simpler table access.
def elf_dynamic_entries(binaries: list[lief.Binary]):
    def generator() -> Iterator[dict[str, Any]]:
        for binary in binaries:
            # super important that these accessors are pulled out of the tight loop
            # as they can be costly
            binary_name = binary.name
            for entry in binary.dynamic_entries:  # pyright: ignore
                yield {"path": binary_name, "tag": entry.tag.name, "value": entry.value}

    return generator


def register(connection: apsw.Connection, binaries: list[lief.Binary]):
    generator = elf_dynamic_entries(binaries)
    # setup columns and access by providing an example of the first entry returned
    generator.columns, generator.column_access = apsw.ext.get_column_names(
        next(generator())
    )
    apsw.ext.make_virtual_module(connection, "elf_dynamic_entries", generator)
