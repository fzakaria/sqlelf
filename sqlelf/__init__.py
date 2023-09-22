from importlib.metadata import PackageNotFoundError, version

import apsw.bestpractice

# forward sqlite logs to logging module
apsw.bestpractice.apply(apsw.bestpractice.recommended)

try:
    __version__ = version("sqlelf")
except PackageNotFoundError:
    # If the package is not installed, don't add __version__
    pass
