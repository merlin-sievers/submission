#!/usr/bin/env python3

from log import eval_log, mute_other_loggers
mute_other_loggers()

from patch_karonte import JobResult
import argparse
import os
import logging
import builtins
import json
from tabulate import tabulate

from dataclasses import asdict, dataclass, field
from itertools import chain
from pathlib import Path

from patched_lib_prepare.prepare_libs import read_scans, prepare
from patched_lib_prepare.scan_entry import Result as PrepareResult, ScanEntry
from parallel import patch_and_test_parallely
from patching.configuration import Config

locks = None

@dataclass
class TestSubject:
    product: str
    cves: list[str]
    compile_flags: str
    results: list[list[PrepareResult]] = field(default_factory=lambda: [])

evaluation_test_subjects = [
    TestSubject(
        'zlib',
        [
            "CVE-2016-9840",
            "CVE-2016-9842",
            "CVE-2016-9843",
        ],
        'Os'
    ),
    TestSubject(
        'libpng',
        [
            "CVE-2018-10087",
        ],
        ''
    ),
    TestSubject(
        'libpcap',
        [
            "CVE-2019-15165",
        ],
        'Os'
    ),
    TestSubject(
        'flac',
        [
            "CVE-2020-22219",
        ],
        'Os'
    ),
    TestSubject(
        'busybox',
        [
            "CVE-2021-42386",
        ],
        ''
    ),
]

def main():
    global evaluation_test_subjects

    eval_log.setLevel(logging.INFO)

    parser = argparse.ArgumentParser()

    _ = parser.add_argument('--karonte-dir', type=Path, default=Path(os.environ.get('KARONTE_DIR', './karonte')))
    _ = parser.add_argument('--full-scan-json', type=Path, default=Path(os.environ.get('FULL_SCAN_JSON', './full-scan.json')))
    _ = parser.add_argument('--filter', default='', help='A filter like "product=zlib" or "cve=CVE-2016-9843".')
    _ = parser.add_argument('--prepare-data-dir', type=Path, default=Path('./prepare-data'))
    _ = parser.add_argument('--toolchains-dir', type=Path, required=False)

    args = parser.parse_args()

    def mute_print(*_args, **_kwargs):  # pyright:ignore[reportUnknownParameterType,reportMissingParameterType]
        pass
    builtins.print = mute_print

    karonte_dir = Path(args.karonte_dir)  # pyright:ignore[reportAny]
    assert karonte_dir.exists()
    full_scan_json_path = Path(args.full_scan_json)  # pyright:ignore[reportAny]
    assert full_scan_json_path.parent.exists()

    eval_filter: str = args.filter  # pyright:ignore[reportAny]
    k, v = ('', '')
    if eval_filter:
        try:
            k, v = tuple(eval_filter.split('='))  
        except ValueError:
            eval_log.error('Filter does not have to correct format. See help page.')
            exit(1)
        k = k.lower()
        assert k in ('product', 'cve')
        if k == 'product':
            evaluation_test_subjects = list(filter(lambda ts: ts.product == v, evaluation_test_subjects))
        if k == 'cve':
            evaluation_test_subjects = list(filter(lambda ts: v in ts.cves, evaluation_test_subjects))

    eval_log.info('Reading scans...')
    all_scans = read_scans(karonte_dir, full_scan_json_path, force_rescan=False)
    eval_log.info('Finished reading scans...')

    if k == 'cve':
        cves_to_test: list[str] = [v]
    else:
        cves_to_test = list(chain.from_iterable([ts.cves for ts in evaluation_test_subjects]))

    # Build scans_by_cve dict
    scans_by_cve: dict[str, list[ScanEntry]] = {}
    for scan in all_scans:
        if scan.cve_number not in cves_to_test:
            continue
        scans = scans_by_cve.get(scan.cve_number, [])
        scans.append(scan)
        scans_by_cve[scan.cve_number] = scans

    # prepare directories and change to prepare directory for preparation step
    pdd: Path = args.prepare_data_dir  # pyright:ignore[reportAny]
    pdd.mkdir(parents=True, exist_ok=True)
    assert args.toolchains_dir is None or isinstance(args.toolchains_dir, Path) # pyright:ignore[reportAny]
    if not args.toolchains_dir:
        toolchains_dir = str((pdd / 'toolchains').absolute())
    else:
        toolchains_dir = str(args.toolchains_dir.absolute())
    os.environ['TOOLCHAINS_DIR'] = toolchains_dir
    previous_cwd = Path('.').resolve()
    os.chdir(pdd)
    prepare_results_dir = Path('results').absolute()
    prepare_results_dir.mkdir(exist_ok=True, parents=True)

    # Preparation step
    for ts in evaluation_test_subjects:
        eval_log.info(f'Preparing for {ts.product} ({len(ts.cves)} CVEs)')
        for cve in ts.cves:
            eval_log.info(f'Preparing for {cve}')
            try:
                scans = scans_by_cve[cve]
            except KeyError:
                eval_log.warning(f'Your "full scan" doesn\'t appear to be so "full". {cve} is missing. Whatever...')
                continue
            cve_results = prepare(
                scans,
                dynlib_only=False,
                compile_flags=ts.compile_flags
            )
            ts.results.append(cve_results)
            _ = (prepare_results_dir / cve).with_suffix('.json').write_text(
                json.dumps(list(map(asdict, cve_results)))
            )
            eval_log.info(f'Prepared for {cve}')
        eval_log.info(f'Prepared for {ts.product}')
    eval_log.info(f'Preparation finished!')

    # Go back to previous directory
    os.chdir(previous_cwd)

    jobs: list[Config] = []

    # Patch and Test
    eval_log.info('Patching and testing...')
    for ts in evaluation_test_subjects:
        for cve_results in ts.results:
            for result in cve_results:
                cfgs = Config.fromPrepareResult(result)
                jobs.extend(cfgs)

    results = filter(
        lambda x: x[1] not in (
            JobResult.UNSUPPORTED_PRODUCT,
            JobResult.UNKNOWN_CVE
        ),
        patch_and_test_parallely(jobs)
    )

    eval_log.info('Patching and testing finished.')

    @dataclass
    class TableEntry:
        cve: str
        product: str
        results_count: dict[JobResult, int]

    results_by_cve: dict[str, TableEntry] = {}
    eval_log.info('Evaluation:')
    for cfg, result in results:
        eval_log.info(f'{result.name}: {cfg.binary_path} -> {cfg.output_path}')
        entry = results_by_cve.get(cfg.cve, TableEntry(cfg.cve, cfg.product, {}))
        count = entry.results_count.get(result, 0)
        entry.results_count[result] = count + 1
        results_by_cve[cfg.cve] = entry

    table: list[list[str | int]] = []
    for entry in results_by_cve.values():
        total = sum(entry.results_count.values())
        results = 3 * [0]
        for result, result_count in entry.results_count.items():
            if result == JobResult.PATCH_FAIL:
                results[1] = result_count
            elif result == JobResult.SUCCESS:
                results[2] = result_count
        results[1] = total - results[1]
        results[0] = total
        row = [entry.cve, entry.product] + results + [f'{round(100 * results[2]/total)}']
        table.append(row)

    eval_log.info('\n' + tabulate(table, headers=('CVE', 'Product', 'Affected', 'Patched', 'Test Passed', 'Percentage')))

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        import traceback
        eval_log.critical(traceback.format_exc())
