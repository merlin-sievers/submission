from .preparer import Builder
from pathlib import Path

class SQLiteBuilder(Builder):

    build_parent: Path = Path('build/sqlite')
