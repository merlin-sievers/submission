from typing import override

from patched_lib_prepare.git import GitBuilder

class GitHubBuilder(GitBuilder):

    owner: str = NotImplemented
    repo: str = NotImplemented

    @override
    @classmethod
    def url(cls) -> str:
        if not cls.owner or not cls.repo:
            raise NotImplementedError(f'Owner and Repo must be specified for this GitHub library ({cls.product}).')
        return f'https://github.com/{cls.owner}/{cls.repo}.git'
