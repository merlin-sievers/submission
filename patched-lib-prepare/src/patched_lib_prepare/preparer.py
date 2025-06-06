from functools import cache
from itertools import groupby
from pathlib import Path
import shutil
from subprocess import run
from collections.abc import Generator
import tarfile
import logging
from zipfile import ZipFile
from cve_bin_tool.cve_scanner import Version  # pyright:ignore[reportMissingTypeStubs]
import lief

from cve_bin_tool.util import VersionInfo  # pyright:ignore[reportMissingTypeStubs]

from patched_lib_prepare.util import detect_toolchain, assert_toolchain_exists, path_has_arch, random_id
from patched_lib_prepare.version import TaggedVersion

from .scan_entry import Result, ResultInstance, ScanEntry

l = logging.getLogger('patched-lib-prepare')

class Dependency:

    def __init__(self, builder_class: type['Builder'], version: Version) -> None:
        self.builder_class: type['Builder'] = builder_class
        self.version: Version = version
        self.builder: 'Builder | None' = None


    def build(self, toolchain: str) -> None:
        if self.builder is not None:
            return
        self.builder = self.builder_class(TaggedVersion(self.version, self.builder_class.get_tag_for_version(self.version)), toolchain, '')
        _ = self.builder.build()

    # def CFLAGS(self) -> list[str]:
    #     raise NotImplementedError('TODO')

    def LDFLAGS(self) -> list[str]:
        if self.builder is None:
            raise NotImplementedError(f'Builder ({self.builder_class}:{self.version}) was not initialized.')
        return list(set(map(lambda p: '-L' + str(p.parent.absolute()), self.builder.output_paths)))

    def INCLUDE_FLAGS(self) -> list[str]:
        if self.builder is None:
            raise NotImplementedError(f'Builder ({self.builder_class}:{self.version}) was not initialized.')
        return list(set(map(lambda p: '-I' + str(p), self.builder.include_paths)))

class Builder:
    build_parent_base: Path = NotImplemented
    outfile_fmt: str = NotImplemented
    url_fmt: str = NotImplemented
    repo_type: str = NotImplemented
    product: str = NotImplemented
    keywords: list[str] = []

    dependency_list: list[tuple[type['Builder'], Version]] = []

    def __init__(self, version: TaggedVersion, toolchain: str, compile_flags: str) -> None:
        if not self.product:
            raise NotImplementedError
        self.version: Version = version.version
        self.tag: str = version.tag
        self.toolchain: str = toolchain
        self.unique_id: str = ''
        self.dependencies: list[Dependency] = [ Dependency(builder_class, version) for (builder_class, version) in self.dependency_list ]
        self.compile_flags: str = ' '.join(map(lambda s: f'-{s}', compile_flags.split()))
        self.build_parent.mkdir(parents = True, exist_ok = True)

    @property
    def include_paths(self) -> list[Path]:
        return list(map(lambda x: x.parent.absolute(), self.output_paths))

    @property
    def build_parent(self) -> Path:
        return self.build_parent_base.with_name(self.build_parent_base.name + self.compile_flags)

    @classmethod
    def is_out_of_scope(cls, _version: Version, _cve: str, _affected_path: Path) -> bool:
        return False

    @classmethod
    def affected_path_seems_valid(cls, affected_path: Path) -> bool:
        if cls.product.lower() in affected_path.name.lower():
            return True
        for keyword in cls.keywords:
            if keyword.lower() in affected_path.name.lower():
                return True
        return False

    @classmethod
    def is_executable(cls) -> bool:
        return False

    @property
    def output_file_fmts(self) -> list[str]:
        raise NotImplementedError

    @property
    def patch(self) -> str | None:
        if '$patch$' in self.tag:
            return self.tag.split('$')[2]
        return None

    @property
    def actual_tag(self) -> str:
        return self.tag.split('$')[0]

    @property
    def prod_id(self) -> str:
        patch = self.patch
        if patch:
            return f'{self.product}:{self.version}-patched-{patch}'
        return f'{self.product}:{self.version}'

    @property
    def repo_dir(self) -> Path:
        unique_str = ''
        if self.unique_id:
            unique_str = '-unique-' + self.unique_id
        patch = self.patch
        if patch:
            patch = f'-patched-{patch}'
        else:
            patch = ''
        return self.build_parent / f'{self.toolchain}-{self.product}-{self.version}{patch}{unique_str}'

    @property
    def repo_filename(self) -> str:
        patch = self.patch
        if patch:
            patch = f'-patched-{patch}'
        else:
            patch = ''
        return f'{self.product}-{self.version}{patch}.{self.repo_type}'

    @property
    def output_repo_file(self) -> Path:
        return self.build_parent / self.repo_filename

    @property
    def expected_download_content_type(self) -> str:
        return {
            'zip': 'application/zip'
        }[self.repo_type]

    @classmethod
    def url(cls) -> str:
        raise NotImplementedError

    @property
    def build_stdout(self) -> Path:
        return Path(str(self.repo_dir) + '.stdout')

    @property
    def build_stderr(self) -> Path:
        return Path(str(self.repo_dir) + '.stderr')

    @property
    def output_paths(self) -> list[Path]:
        return [self.repo_dir / (output_file_fmt % {'lib': self.product, 'version': self.version, 'tag': self.tag}) for output_file_fmt in self.output_file_fmts]

    def fetch_archive(self) -> bool:
        raise NotImplementedError

    def unpack(self, force: bool = False) -> Path:
        out_dir: Path = self.repo_dir
        if out_dir.exists():
            if force:
                shutil.rmtree(out_dir)
            else:
                return out_dir
        _ = self.fetch_archive()
        l.debug(f'Unpacking {self.output_repo_file} to {out_dir}')
        if self.output_repo_file.suffix == '.zip':
            with ZipFile(self.output_repo_file, 'r') as f:
                f.extractall(out_dir)
        elif self.output_repo_file.name.endswith('.tar.gz'):
            with tarfile.open(self.output_repo_file, 'r:*') as tar:
                tar.extractall(path=out_dir)
        return out_dir

    @property
    def build_commands(self) -> str:
        raise NotImplementedError

    def prepare_build_commands(self) -> str:
        return ' && '.join(filter(lambda x: len(x.strip()) > 0, self.build_commands.splitlines()))

    def build(self, unique: bool = False) -> Path | None:
        _ = self.unpack()
        def unique_check() -> Path | None:
            if unique:
                non_unique_dir = self.repo_dir
                self.unique_id = random_id(9)
                unique_dir = self.repo_dir
                _ = shutil.copytree(non_unique_dir, unique_dir, symlinks=True)
                return unique_dir
        if all(map(lambda x: x.is_file(), self.output_paths)):
            l.debug(f'Output path(s) {", ".join(map(str, self.output_paths))} already exist. Skipping...')
            return unique_check()
        else:
            l.debug(f'Output path(s) {", ".join(map(str, self.output_paths))} do not exist yet. Compiling...')

        for dependency in self.dependencies:
            _ = dependency.build(self.toolchain)

        if not self.build_commands:
            raise NotImplementedError(f'No build commands were specified for "{self.prod_id}"')
        cmds = self.prepare_build_commands()
        l.info(f"Compiling {self.product} {self.version}")
        completed_process = run(cmds, shell=True, capture_output=True, cwd=self.repo_dir)
        l.info(f"{self.output_paths}, {self.repo_dir}")
        for s in self.output_paths:
            l.info(f"{s}")
        if completed_process.returncode != 0:
            l.error(f'Failed to compile "{self.prod_id}". Output of the compilation process is stored in {self.build_stdout} and {self.build_stderr}')
            _ = Path(str(self.repo_dir) + '.cmd').write_text(cmds)
            _ = self.build_stdout.write_bytes(completed_process.stdout)
            _ = self.build_stderr.write_bytes(completed_process.stderr)
            exit(1)
        if not all(map(lambda x: x.is_file(), self.output_paths)):
            l.error(f'Output file for compilation is missing. Was expecting something here: {self.output_paths}. Output of the compilation process is stored in {self.build_stdout} and {self.build_stderr}')
            _ = Path(str(self.repo_dir) + '.cmd').write_text(cmds)
            _ = self.build_stdout.write_bytes(completed_process.stdout)
            _ = self.build_stderr.write_bytes(completed_process.stderr)
            exit(1)
        return unique_check()

    @classmethod
    def get_manual_patch_for_version(cls, _cve: str, _version: Version) -> str | None:
        return None

    def test_is_prepared(self) -> bool:
        raise NotImplementedError

    def prepare_for_tests_commands(self) -> str:
        return ''

    def prepare_for_tests(self) -> None:
        cmds = ' && '.join(filter(lambda x: len(x.strip()) > 0, self.prepare_for_tests_commands().splitlines()))
        if not cmds:
            return
        completed_process = run(cmds, shell=True, capture_output=True, cwd=self.repo_dir)
        if completed_process.returncode != 0:
            l.error(f'Failed to prepare tests for "{self.prod_id}". Output of the preparation process is stored in {self.build_stdout} and {self.build_stderr}')
            _ = Path(str(self.repo_dir) + '.cmd').write_text(cmds)
            _ = self.build_stdout.write_bytes(completed_process.stdout)
            _ = self.build_stderr.write_bytes(completed_process.stderr)
            exit(1)
        if not self.test_is_prepared():
            l.error(f'test was not prepared successfully for {self.repo_dir}')
            exit(1)
        l.info(f"Prepared tests for {self.repo_dir.name}")

    @property
    def ldflags(self) -> list[str]:
        result: list[str] = []
        for dep in self.dependencies:
            result.extend(dep.LDFLAGS())
        return result

    @property
    def include_flags(self) -> list[str]:
        result: list[str] = []
        for dep in self.dependencies:
            result.extend(dep.INCLUDE_FLAGS())
        return result

    @classmethod
    def get_all_tags(cls) -> list[str]:
        raise NotImplementedError

    @classmethod
    def get_all_tags_by_version(cls) -> set[Version]:
        return set(map(Version, cls.get_all_tags()))

    @classmethod
    def mangle_version(cls, version: str) -> Generator[str]:
        with_underscores = version.replace('.', '_')
        yield version
        yield with_underscores
        yield f'v{version}'
        yield f'v{with_underscores}'
        yield f'V{version}'
        yield f'V{with_underscores}'
        yield f'{cls.product}-{version}'

    @classmethod
    def get_version_for_tag(cls, _tag: str) -> Version:
        raise NotImplementedError

    @classmethod
    def try_get_patched_version(cls, _affected_version: str, _affected_versions: VersionInfo, _cve: str) -> TaggedVersion:
        raise NotImplementedError

    @classmethod
    def get_tag_for_version(cls, version: str) -> str:
        return cls.get_all_tags()[cls.get_tag_index_for_version(version)]

    @classmethod
    @cache
    def get_tag_index_for_version(cls, version: str) -> int:
        def _no_v_prefix(v: str) -> str:
            if v.startswith('v'):
                return v[1:]
            return v

        def _v_prefix(v: str) -> str:
            return f'v{_no_v_prefix(v)}'

        tags = cls.get_all_tags()
        def _generate_attempts() -> Generator[str]:
            yield _no_v_prefix(version)
            yield _v_prefix(version)
            for mangling in cls.mangle_version(_no_v_prefix(version)):
                yield mangling

        for attempt in _generate_attempts():
            try:
                index = tags.index(attempt)
            except ValueError:
                l.debug(f'There is no "{attempt}" for {cls.product}')
                # l.debug(str(tags))
                continue
            if index == 0:
                raise Exception(f'{cls.product}: There does not appear to be a newer tag than the one referring to the still vulnerable version "{version}".')
            return index
        raise Exception(f'{cls.product}: Failed to find version "{version}" in all tags. Could not guess the excluding end.')

    @classmethod
    def get_following_tags(cls, _tag: str) -> Generator[str]:
        raise NotImplementedError

class Preparer:

    def __init__(self, scan_entry: ScanEntry, builder_class: type[Builder], compile_flags: str) -> None:
        self.builder_class: type[Builder] = builder_class
        self.product: str = scan_entry.product
        self.specific_version: str = scan_entry.specific_version
        self.version: VersionInfo = scan_entry.version
        self.cve: str = scan_entry.cve_number
        self.paths: list[Path] = scan_entry.paths
        self.lief: lief.Binary | None = None
        self.compile_flags = compile_flags

    @property
    @cache
    def patched_version(self) -> TaggedVersion:
        manual_patch = self.builder_class.get_manual_patch_for_version(self.cve, Version(self.specific_version))
        if manual_patch:
            return TaggedVersion(Version(self.specific_version), tag = manual_patch)

        if self.version.end_excluding:
            return TaggedVersion(Version(self.version.end_excluding), self.builder_class.get_tag_for_version(self.version.end_excluding))

        try:
            return self.builder_class.try_get_patched_version(self.specific_version, self.version, self.cve)
        except NotImplementedError:
            pass

        def patternize(t: str):
            v = self.builder_class.get_version_for_tag(t)
            patternized = ''.join('X' if c.isalpha() else '0' if c.isdigit() else c for c in v)
            return ''.join(char for char, _ in groupby(patternized))

        if self.version.end_including:
            end_including = self.version.end_including
            e_incl_tag = self.builder_class.get_tag_for_version(end_including)
            e_incl_pattern = patternize(e_incl_tag)
            for next_tag in self.builder_class.get_following_tags(e_incl_tag):
                next_version = self.builder_class.get_version_for_tag(next_tag)
                if next_version <= Version(self.specific_version):
                    l.error(f'Deemed version {next_version} to be the patched_version of {Version(self.specific_version)} ({self.cve}), but it appears to be older.')
                    raise NotImplementedError
                if not e_incl_pattern ==  patternize(next_tag):
                    l.warning(f'Patterns of the inclusive end tag "{e_incl_tag}" and the deemed next tag "{next_tag}" do not match. Skipping...')
                    continue
                patched_version = TaggedVersion(next_version, next_tag)
                l.info(f"Guessed version {patched_version}, as it is the next tag.")
                return patched_version


        if self.specific_version not in self.version.version_list:
            raise NotImplementedError(f'Cannot handle this: There is neither end_excluding nor end_including for {self.cve} and this version is not even in the version list (which has {len(self.version.version_list)} entries)')

        specific_tag = self.builder_class.get_tag_for_version(self.specific_version)
        specific_tag_pattern = patternize(specific_tag)

        version_list = list(map(Version, self.version.version_list))
        followers = self.builder_class.get_following_tags(specific_tag)
        for next_tag in followers:
            next_version = self.builder_class.get_version_for_tag(next_tag)

            if next_version in version_list:
                continue

            # Sanity check
            # There might be tags that are not version numbers.
            # This check should detect whether the tag has a similar naming convention.
            next_tag_pattern = patternize(next_tag)
            if specific_tag_pattern != next_tag_pattern:
                l.error(f'While trying to find the next non-vulnerable tag, a version pattern mismatch happened. Is this maybe not a version tag? "{next_tag}"')
                raise NotImplementedError

            if Version(next_version) <= Version(self.specific_version):
                l.error(f'Deemed version {next_version} to be the patched_version of {self.specific_version} ({self.cve}), but it appears to be older. or the same.')
                continue

            l.info(f'Guessed version {next_tag}, as it appears to be the next non-vulnerable tag.')
            return TaggedVersion(next_version, next_tag)
        raise NotImplementedError(f'Could not find non-vulnerable tag more recent than the current tag ({self.specific_version}).')

    def _select_affected_patched_path(self, candidates: list[Path], affected: Path) -> Path:
        if len(candidates) == 1:
            return candidates[0]
        def _mini_stem(p: Path) -> str:
            return p.name.split('.')[0]
        same_stem = list(filter(lambda candidate: _mini_stem(candidate) == _mini_stem(affected), candidates))
        if len(same_stem) == 1:
            return same_stem[0]
        raise NotImplementedError(f'Did not yet implement a selection algorithm sophisticated enough: {candidates} | {affected}')

    def prepare(self) -> Result:
        instances: list[ResultInstance] = []
        for path in self.paths:
            if not self.builder_class.affected_path_seems_valid(path):
                l.warning(f'Skipping. This affected path does not seem to belong to product "{self.product}": {path}')
                continue
            if self.builder_class.is_out_of_scope(Version(self.specific_version), self.cve, path) or \
                self.builder_class.is_out_of_scope(Version(self.patched_version), self.cve, path):
                continue
            self.lief = lief.parse(path)  # pyright:ignore[reportUnknownMemberType]
            if not self.lief:
                raise NotImplementedError(f'Failed to parse file using lief: {path}')
            toolchain = detect_toolchain(path, self.lief)
            assert_toolchain_exists(toolchain)
            patch_builder = self.builder_class(self.patched_version, toolchain, self.compile_flags)
            specific_tag = self.builder_class.get_tag_for_version(self.specific_version)
            test_builder = self.builder_class(TaggedVersion(Version(self.specific_version), specific_tag), toolchain, self.compile_flags)
            _ = patch_builder.build()
            assert all(map(lambda r: path_has_arch(r, 'arm32'), patch_builder.output_paths))
            unique_test_dir = test_builder.build(unique = True)
            test_builder.prepare_for_tests()
            assert unique_test_dir
            instances.append(ResultInstance(
                affected_path = str(path.absolute()),
                patched_path = str(self._select_affected_patched_path(patch_builder.output_paths, path).absolute()),
                toolchain = toolchain,
                test_dir = str(unique_test_dir.absolute())
            ))
        patched_version = TaggedVersion(Version('UNASSIGNED'), 'UNASSIGNED')
        if len(instances) > 0:
            patched_version = self.patched_version
        return Result(
            product = self.product,
            version = self.specific_version,
            cve = self.cve,
            patched_version = patched_version,
            instances = instances
        )
