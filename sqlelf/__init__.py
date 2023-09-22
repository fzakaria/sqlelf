import apsw.bestpractice
from importlib.metadata import version, PackageNotFoundError

# forward sqlite logs to logging module
apsw.bestpractice.apply(apsw.bestpractice.recommended)

try:
    __version__ = version("sqlelf")
except PackageNotFoundError:
    # If the package is not installed, don't add __version__
    pass
