import re
from collections import OrderedDict
from typing import Dict

import lief
import sh  # pyright: ignore


def libraries(binary: lief.Binary) -> Dict[str, str]:
    """Use the interpreter in a binary to determine the path of each linked library"""
    interpreter = sh.Command(binary.interpreter)  # pyright: ignore
    resolution = interpreter("--list", binary.name)
    result = OrderedDict()
    # TODO: Figure out why `--list` and `ldd` produce different outcomes
    # specifically for the interpreter.
    # https://gist.github.com/fzakaria/3dc42a039401598d8e0fdbc57f5e7eae
    for line in resolution.splitlines():  # pyright: ignore
        m = re.match(r"\s*([^ ]+) => ([^ ]+)", line)
        if not m:
            continue
        soname, lib = m.group(1), m.group(2)
        result[soname] = lib
    return result
