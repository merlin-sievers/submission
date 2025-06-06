
from dataclasses import dataclass
from typing import Callable

from cve_bin_tool.version_compare import Version  # pyright:ignore[reportMissingTypeStubs]


@dataclass
class TaggedVersion:
    version: Version
    tag: str

@dataclass
class VersionSpecificCommands:
    start: Version
    end: Version
    customizer: Callable[[str], str]

    def __contains__(self, item: Version) -> bool:
        return item <= self.end and item >= self.start

    def customize_commands(self, default_commands: str) -> str:
        return self.customizer(default_commands)

@dataclass
class VSC:  # VersionSpecificChanges
    start: Version
    end: Version
    config_overwrites: dict[str,str]
    patches: list[str]
    test_patches: list[str]
    make_args: list[str]

    def is_in_range(self, v: Version) -> bool:
        return v >= self.start and v <= self.end

