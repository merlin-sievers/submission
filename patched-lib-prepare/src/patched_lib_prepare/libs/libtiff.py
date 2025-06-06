from pathlib import Path
from .preparer import Builder

class LibTIFFBuilder(Builder):

    build_parent: Path = Path('build/libtiff')
