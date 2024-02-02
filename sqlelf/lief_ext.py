# pyright: strict
from typing import TYPE_CHECKING, Any, Optional

# ELF.pyi has no matching py file since it's a c extension
# pyright: reportMissingModuleSource=false
# https://github.com/microsoft/pyright/issues/5950
import lief.ELF

# Let's make sure type checking works for this proxy class
# https://stackoverflow.com/questions/71365594/how-to-make-a-proxy-object-with-typing-as-underlying-object-in-python
if TYPE_CHECKING:
    base = lief.ELF.Binary
else:
    base = object


class Binary(base):
    """Proxy the lief.Binary object to add a path attribute.

    As of https://github.com/lief-project/LIEF/issues/839 the name
    attribute in lief.Binary was removed. Rather than passing around
    a tuple let's create a nice proxy class.
    """

    def __init__(self, path: str):
        self.path = path
        self.__binary: Optional[lief.ELF.Binary] = lief.ELF.parse(  # pyright: ignore
            path
        )

    if not TYPE_CHECKING:

        def __getattr__(self, attr: str) -> Any:
            return getattr(self.__binary, attr)

    @staticmethod
    def is_elf(path: str) -> bool:
        return lief.is_elf(path)
