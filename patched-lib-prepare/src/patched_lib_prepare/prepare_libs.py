#!/usr/bin/env python3

import argparse
from contextlib import ExitStack
from dataclasses import asdict
from functools import cache
import logging
import sys
import tarfile
from typing import Any
import colorlog
import json
from pathlib import Path
import copy
from tqdm import tqdm

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

from patched_lib_prepare.libs.busybox import BusyboxBuilder
from patched_lib_prepare.libs.libFLAC import LibFLACBuilder
from patched_lib_prepare.libs.libpcap import LibPCAPBuilder
from patched_lib_prepare.libs.zlib import ZLibBuilder
from patched_lib_prepare.libs.libpng import LibPNGBuilder

from patched_lib_prepare.preparer import Preparer
from patched_lib_prepare.scan_entry import Result, ScanEntry
from patched_lib_prepare.util import path_has_arch

SUPPORTED_LIBS = {
    "zlib": ZLibBuilder,
    "busybox": BusyboxBuilder,
    "flac": LibFLACBuilder,
    "libflac": LibFLACBuilder,
    "libpcap": LibPCAPBuilder,
    "libpng": LibPNGBuilder,
}

l = logging.getLogger('patched-lib-prepare')
l.setLevel(logging.ERROR)

formatter = colorlog.ColoredFormatter(
    "%(log_color)s%(levelname)-8s%(reset)s %(blue)s%(message)s",
    datefmt=None,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
    },
)

stream_handler = logging.StreamHandler()

stream_handler.setFormatter(formatter)

l.addHandler(stream_handler)

def rescan(karonte_dir: Path | None, output_path: Path):
    if not karonte_dir:
        l.error(f'Cannot rescan karonte dir: {karonte_dir}')
        exit(1)
    l.info("Rescanning...")
    from cve_bin_tool import cli  # pyright:ignore[reportMissingTypeStubs]
    _returncode = cli.main(['rescan', '--affected-versions', '-f', 'json', '-o', str(output_path), str(karonte_dir)])  # pyright:ignore[reportUnknownMemberType,reportUnknownVariableType]
    if not output_path.exists():
        l.error("cve-bin-tool scan did not result in an output scan file.")
        exit(1)

@cache
def is_dynlib(path: Path) -> bool:
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            return elf.header.e_type == 'ET_DYN'  # pyright:ignore[reportUnknownMemberType,reportUnknownVariableType]
    except ELFError:
        l.warning(f"Error parsing file. Is it really an ELF file? {path}")
        return False

def to_only_matching_arch(entry: ScanEntry) -> ScanEntry:
    filtered_paths = filter(lambda p: path_has_arch(p, "arm32"), entry.paths)
    entry_copy = copy.deepcopy(entry)
    entry_copy.paths = list(filtered_paths)
    return entry_copy

def to_dynlib_only(entry: ScanEntry) -> ScanEntry:
    if SUPPORTED_LIBS[entry.product].is_executable():
        return entry
    filtered_paths = filter(is_dynlib, entry.paths)
    entry_copy = copy.deepcopy(entry)
    entry_copy.paths = list(filtered_paths)
    return entry_copy

def prepare(scans: list[ScanEntry], dynlib_only: bool, compile_flags: str) -> list[Result]:
    filtered_libs_scan = filter(lambda entry: entry.product in SUPPORTED_LIBS.keys(), scans)
    filtered_paths_scan = map(to_only_matching_arch, filtered_libs_scan)
    if dynlib_only:
        filtered_paths_scan = map(to_dynlib_only,  filtered_paths_scan)
    removed_nopath_scan = filter(lambda entry: len(entry.paths) > 0, filtered_paths_scan)
    filtered_scan = removed_nopath_scan


    def prepare_entry(scan_entry: ScanEntry) -> Result:
        try:
            builder_class = SUPPORTED_LIBS[scan_entry.product]
        except KeyError:
            raise NotImplementedError(f"No builder implemented for product {scan_entry.product}.")
        preparer = Preparer(scan_entry, builder_class, compile_flags)
        result: Result = preparer.prepare()
        return result

    prepared_libs = list(filter(lambda e: len(e.instances) > 0, map(prepare_entry, filtered_scan)))
    return prepared_libs

def read_scans(karonte_dir: Path | None, path: Path, force_rescan: bool) -> list[ScanEntry]:
    if path.exists():
        if not path.is_file():
            raise Exception("Why is scan-json-result something different from a file? Stop this.")
        if force_rescan:
            l.info("Scan json file exists, but --force-rescan was supplied. Scanning again...")
            rescan(karonte_dir, path)
    else:
        rescan(karonte_dir, path)

    scan_any: list[Any] = json.loads(path.read_text())  # pyright:ignore[reportAny,reportExplicitAny]
    mapped_scan = map(lambda e_any: ScanEntry(e_any), tqdm(scan_any, desc='All scans'))  # pyright:ignore[reportAny]

    return list(mapped_scan)

def assert_karonte_exists(karonte_dir: Path):
    if not karonte_dir.is_dir():
        l.warning("No karonte dir is found. Default is ./karonte")
        try:
            l.info("Trying to download karonte dataset automatically.")
            tar_path = './karonte_dataset.tar.gz'
            if not Path(tar_path).exists():
                import gdown
                gdown.download('https://drive.google.com/file/d/1-VOf-tEpu4LIgyDyZr7bBZCDK-K2DHaj/view', fuzzy=True, output=tar_path)
            karonte_dir.mkdir(parents=True)
            with tarfile.open(tar_path) as tf:
                tf.extractall(path=karonte_dir)
        except Exception as e:
            import traceback
            l.error(f"Failed to download the karonte dataset automatically. Error: {traceback.format_exc()}")
            l.error("If you have not downloaded the karonte dataset, do so at https://drive.google.com/file/d/1-VOf-tEpu4LIgyDyZr7bBZCDK-K2DHaj/view")
            l.error("The tarfile then needs to be unpacked and the resulting folder can be specified using --karonte-dir")
            exit(1)

def main(karonte_dir: Path, scan_json_result: Path, force_rescan: bool, output_file: str, dynlib_only: bool, force_overwrite: bool, compile_flags: str):
    if output_file != '-' and Path(output_file).exists() and not force_overwrite:
        raise FileExistsError(f'Output file "{output_file}" already exists.')

    assert_karonte_exists(karonte_dir)

    scans = read_scans(karonte_dir, scan_json_result, force_rescan)

    result_data = json.dumps(list(map(asdict, prepare(scans, dynlib_only, compile_flags))))

    with ExitStack() as stack:
        if output_file == "-":
            file = sys.stdout
        else:
            file = stack.enter_context(open(output_file, "w"))
        _ = file.write(result_data)
        if output_file == "-":
            print()



def argv_main():
    parser = argparse.ArgumentParser()
    _ = parser.add_argument('--karonte-dir', type=Path, default=Path('./karonte'))
    _ = parser.add_argument('--scan-json-result', type=Path, default=Path('./karonte-scan.json'))
    _ = parser.add_argument('--force-rescan', action='store_true', default=False)
    _ = parser.add_argument('--output-file', default='-', help='The default value is "-" which is interpreted as stdout.')
    _ = parser.add_argument('--log-level', choices=('error', 'warning', 'info', 'debug'), default='error')
    _ = parser.add_argument('--dynlib-only', default=False, action='store_true')
    _ = parser.add_argument('--force-overwrite', '-f', default=False, action='store_true')
    _ = parser.add_argument('--compile-flags', default='')

    args = parser.parse_args()
    l.setLevel({
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG,
    }[args.log_level])  # pyright:ignore[reportAny]
    main(args.karonte_dir, args.scan_json_result, args.force_rescan, args.output_file, args.dynlib_only, args.force_overwrite, args.compile_flags) # pyright:ignore[reportAny]

if __name__ == "__main__":
    argv_main()
