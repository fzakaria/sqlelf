#! /usr/bin/env python
"""Go through /bin and print out the number of symbols in each binary."""

import itertools
import json
import os
import subprocess
from collections import defaultdict

data = defaultdict(lambda: 0)


def is_elf_file(filepath):
    try:
        with open(filepath, "rb") as file:
            # Read the first four bytes of the file
            magic_number = file.read(4)
    except FileNotFoundError:
        return False
    except IOError:
        return False

    # Check if the magic number matches the ELF signature
    return magic_number == b"\x7fELF"


for root, dirs, files in itertools.chain(
    os.walk("/bin"), os.walk("/usr/bin"), os.walk("/lib/x86_64-linux-gnu")
):
    for file in files:
        full_path_file = os.path.join(root, file)
        if not os.path.isfile(full_path_file) or not os.access(full_path_file, os.X_OK):
            pass
        if not is_elf_file(full_path_file):
            continue  # skip non-ELF files
        result = subprocess.run(
            f"readelf -s {full_path_file} | wc -l",
            capture_output=True,
            text=True,
            shell=True,
        )
        num_symbols = int(result.stdout)
        data[full_path_file] = num_symbols

with open("symbols.json", "w") as f:
    json.dump(data, f, indent=2)
