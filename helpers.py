from dataclasses import dataclass
from pathlib import Path

@dataclass
class CVEFunctionInfo:
    patch_fn: str
    vuln_fn: str
    search_for_original: bool = True

def get_sysroot(firmware: Path) -> Path:
    p = firmware
    while p.name in ('lib', 'usr') or p.parent.name in ('lib', 'usr'):
        p = p.parent
    return p
