from setuptools import setup, find_packages
import os
import subprocess

def install_git_repo(url, repo_name):
    subprocess.check_call(['git', 'clone', url])
    subprocess.check_call(['pip', 'install', '-e', repo_name])

# These download the repos via SSH so the user needs to make sure to have an SSH key (this is mandatory since Aug 2021)
# The packages need to be downloaded in this order (patcherex depends on povsim and compilerex)
install_git_repo('git@github.com:mechaphish/povsim.git', 'povsim')
install_git_repo('git@github.com:mechaphish/compilerex.git', 'compilerex')
install_git_repo('git@github.com:angr/patcherex.git', 'patcherex')
install_git_repo('git@github.com:axt/angr-utils.git', 'angr-utils')

setup(
    name='variable-backward-slice',
    version='0.0.1',
    packages=find_packages(),
    install_requires=[
        'angr~=9.2.72',
        'tracer~=0.1',
        'claripy~=9.2.72',
        'setuptools~=68.2.2',
        'monkeyhex~=1.7.4',
        'archinfo~=9.2.72',
        'networkx~=3.1',
        'lief~=0.13.2',
        'cle~=9.2.72',
        'pyelftools~=0.30',
        'capstone~=5.0.0.post1',
        'fidget~=0.1.3',
        'pyvex~=9.2.72',
        'psutil~=5.9.5',
        'termcolor~=2.3.0',
        'requests~=2.31.0',
        'argparse~=1.4.0',
        'bingraphvis~=0.4.0',
        'pydot~=1.4.2',
        'Pygments~=2.16.1',
        'PyYAML~=6.0.1'
    ],
)
