# from functools import cache
# from typing import override
# from patched_lib_prepare.preparer import Builder
#
# import urllib.request
#
# class GitLabPreparer(Builder):
#     owner: str = ''
#     repo: str = ''
#     gitlab_base: str = 'https://gitlab.com'
#
#     @classmethod
#     @override
#     def get_all_tags(cls) -> list[str]:
#         return cls.get_all_gl_tags()
#
#     @classmethod
#     @cache
#     def get_all_gl_tags(cls) -> list[str]:
#         req = urllib.request.Request(f'{cls.gitlab_base}/api/v4/projects/{cls.owner}%2F{cls.repo}/repository/tags')
#         with urllib.request.urlopen(req) as response:
#             raise NotImplementedError
#
#

