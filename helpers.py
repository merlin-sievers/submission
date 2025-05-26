from dataclasses import dataclass

@dataclass
class CVEFunctionInfo:
    patch_fn: str
    vuln_fn: str
    search_for_original: bool = True
