from setuptools import setup, find_packages

setup(
    name='patcherexMM',
    version='1.2',
    description='The patcherexMM',
    packages=find_packages(),
    scripts=["patcherexMM/patcherexMM"],
    install_requires=[
        'angr',
        'capstone',
        'keystone-engine',
        'psutil',
        'povsim',
        'compilerex',
        'shellphish-qemu',
        'fidget',
        'pyyaml',
        'pyelftools',
        'python-magic',
        'termcolor',
        'tracer',
   ],
)
