#! /usr/bin/env python
"""Go through /bin and print out the number of symbols in each binary."""

import json
import os
import subprocess
from collections import defaultdict

data = defaultdict(lambda: 0)

for root, dirs, files in os.walk("/bin"):
    for file in files:
        full_path_file = os.path.join(root, file)
        if not os.path.isfile(full_path_file) or not os.access(full_path_file, os.X_OK):
            pass
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
