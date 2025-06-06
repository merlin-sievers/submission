
from collections.abc import Generator
from functools import cache
import logging
from pathlib import Path
from typing import override

from cve_bin_tool.version_compare import Version  # pyright:ignore[reportMissingTypeStubs]
from git import Diff, DiffIndex, Repo, TagReference
from patched_lib_prepare.preparer import Builder

l = logging.getLogger('patched-lib-prepare')

class GitBuilder(Builder):
    _url: str = NotImplemented
    repo_type: str = 'tar.gz'

    @override
    @classmethod
    def url(cls) -> str:
        return cls._url

    @classmethod
    @cache
    def _explorable_repo(cls) -> Repo:
        expl_dir = Path('explorable') / cls.product
        if not expl_dir.is_dir():
            expl_dir.mkdir(parents = True)
            repo = Repo.clone_from(cls.url(), expl_dir)
        else:
            repo = Repo(expl_dir)
        return repo

    @override
    def fetch_archive(self) -> bool:
        if self.output_repo_file.is_file():
            return False
        repo = self._explorable_repo()
        head_reference = repo.head.reference
        tag_ref = repo.tag(self.actual_tag)
        # _ = repo.head.reference.set_reference(tag_ref.commit)
        _ = repo.head.reset(tag_ref, index=True, working_tree=True)
        # ct = self.commit_tail
        # if ct:
        #     patches_for_commits = map(self.get_commit_as_patch, ct.split('-'))
        #     for patches_for_commit in patches_for_commits:
        #         for patch in patches_for_commit:
        #             print(patch.diff)
        with open(self.output_repo_file, 'wb') as archive_file:
            _ = repo.archive(archive_file, format=self.repo_type)
        repo.head.reference = head_reference
        assert self.output_repo_file.is_file()
        return True

    @classmethod
    @override
    def get_all_tags(cls) -> list[str]:
        return list(map(lambda x: x.name, cls.get_all_git_tags()))

    @classmethod
    @cache
    def get_all_git_tags(cls) -> list[TagReference]:
        l.info(f'Fetching git tags for {cls.product}...')
        repo = cls._explorable_repo()
        tags = list(map(lambda x: Version(x.name), repo.tags))
        sorted_tags = list(map(repo.tag, sorted(tags)))
        l.debug(f"Tags: {sorted_tags}")
        return sorted_tags

    @classmethod
    def get_tag(cls, tag_str: str) -> TagReference:
        tag_ref = cls._explorable_repo().tag(tag_str)
        try:
            _ = tag_ref.tag
        except ValueError:
            raise NotImplementedError(f'Ref does not exist: {tag_str}')
        if not tag_ref.is_valid():
            raise NotImplementedError(f'Could not find tag for tag name: {tag_str}')
        return tag_ref

    @override
    @classmethod
    def get_tag_for_version(cls, version: str) -> str:
        for variant in cls.mangle_version(version):
            try:
                return cls.get_tag(variant).name
            except NotImplementedError:
                pass
        raise NotImplementedError(f'Could not find a tag for version "{version}" ({cls.product}). Maybe another mangle needs to be implemented.')

    @override
    @classmethod
    def get_following_tags(cls, tag: str) -> Generator[str]:
        tags = list(cls.get_all_git_tags())
        skipped: bool = False
        for t in tags:
            if skipped:
                yield t.name
            else:
                skipped = t.name == tag

    @classmethod
    def get_commit_as_patch(cls, commit: str) -> DiffIndex[Diff]:
        return cls._explorable_repo().commit(commit).diff(f'{commit}~1', create_patch=True)

