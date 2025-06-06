from dataclasses import dataclass
from functools import cache
import logging
from pathlib import Path
import tarfile
import zipfile

from cve_bin_tool.output_engine.util import VersionInfo  # pyright:ignore[reportMissingTypeStubs]

from patched_lib_prepare.version import TaggedVersion

l = logging.getLogger('patched-lib-prepare')

@cache
def _parse_version_range(range_str: str) -> VersionInfo:
    s_incl, s_excl, e_incl, e_excl, v_list = ('', '', '', '', [])
    if range_str == '-':
        pass
    elif range_str.startswith('>= '):
        s_incl = range_str[3:]
    elif range_str.startswith('> '):
        s_excl = range_str[2:]
    elif range_str.startswith('<= '):
        e_incl = range_str[3:]
    elif range_str.startswith('< '):
        e_excl = range_str[2:]
    elif range_str.startswith('list: '):
        v_list = range_str[len('list: '):].split(', ')
    else:
        split = range_str.split(' - ')
        assert len(split) == 2
        start = split[0][1:]
        end = split[1][:-1]

        if range_str.startswith('['):
            s_incl = start
        elif range_str.startswith('('):
            s_excl = start
        else:
            raise Exception(f'Failed to parse version range "{range_str}": First letter should be a "(" or "[" at this point.')

        if range_str.endswith(']'):
            e_incl = end
        elif range_str.endswith(')'):
            e_excl = end
        else:
            raise Exception(f'Failed to parse version range "{range_str}": First letter should be a ")" or "]" at this point.')

    # if not e_excl:
    #     l.debug(f'Could not find an excluding end for version range "{range_str}". This means this program will have to "guess".')
    return VersionInfo(
        start_including=s_incl,
        start_excluding=s_excl,
        end_including=e_incl,
        end_excluding=e_excl,
        version_list=v_list
    )

def _try_get_fixed_path(broken_path_str: str) -> Path | None:
    if Path(broken_path_str).is_file():
        return Path(broken_path_str)
    if not ' contains ' in broken_path_str:
        raise NotImplementedError(f'The file does not exist and it also is not a " contains " string? I don\'t know what to do with this: {broken_path_str}')
    p_parts = broken_path_str.split(' contains ')
    if len(p_parts) != 2:
        raise NotImplementedError(f'Parsing this path is not supported yet: {broken_path_str}')

    container = p_parts[0]
    contained = p_parts[1]

    if container.endswith('.tar.gz') and contained.startswith('.tar.gz.extracted'):
        new_p = Path(container).parent / Path(contained[len('.tar.gz.extracted/'):])
        result = Path(new_p)
        if not result.exists():
            # new_p2 = container + contained[len('.tar.gz'):]
            # if not Path(new_p2).exists():
            raise NotImplementedError(f'Tried to correct " contains " path, but it does not exist: {broken_path_str} -> {new_p}')
        return result
    elif container.endswith('.tar.gz') and contained.startswith('/'):
        tf_path = Path(container)
        output_dir = tf_path.with_name(tf_path.name + '.extracted')
        if not output_dir.exists():
            l.info(f"Extracting tarball: {tf_path} -> {output_dir}")
            output_dir.mkdir(parents=False, exist_ok=True)
            with tarfile.open(tf_path, 'r:*') as tar:
                tar.extractall(path=output_dir)
        return _try_get_fixed_path(str(output_dir / contained[1:]))
    elif container.endswith('.zip') and contained.startswith('/'):
        zip_path = Path(container)
        output_dir = zip_path.with_name(zip_path.name + '.extracted')
        if not output_dir.exists():
            l.info(f"Extracting zip: {zip_path} -> {output_dir}")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(path=output_dir)
        return _try_get_fixed_path(str(output_dir / contained[1:]))
    elif container.endswith('.cab') and contained.endswith('.ocx'):
        return None
    else:
        raise NotImplementedError(f"This path is not in a known format. I cannot fix it: {broken_path_str}")

@dataclass
class ResultInstance:
    affected_path: str
    patched_path: str
    toolchain: str
    test_dir: str

@dataclass
class Result:
    product: str
    version: str
    cve: str
    patched_version: TaggedVersion
    instances: list[ResultInstance]

@dataclass
class ScanEntry:
    vendor: str
    product: str
    specific_version: str
    location: str
    cve_number: str
    severity: str
    score: str
    source: str
    cvss_version: str
    cvss_vector: str
    paths: list[Path]
    remarks: str
    comments: str
    patched_version: str | None
    compiled_patches: list[Path]

    def __init__(self, args: dict[str, str]) -> None:
        paths_str = args.pop('paths')
        for k,v in args.items():
            if k in self.__dataclass_fields__:
                self.__setattr__(k, v)
        # TODO also parse extracted tarfiles with keyword " contains "
        paths: set[Path] = set()
        for p in paths_str.split(", "):
            fixed_path = _try_get_fixed_path(p)
            if fixed_path:
                paths.add(fixed_path)

        self.specific_version = args['version']
        self.version: VersionInfo = _parse_version_range(args['affected_versions'])

        self.paths = list(paths)
