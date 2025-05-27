#!/usr/bin/env python3

from dataclasses import asdict
from pathlib import Path
import json
import logging

import lief
import evaluate_karonte
from log import eval_log
from patching.configuration import Config

FIXED_PATCH_SIZE = 0x80000

import matplotlib.pyplot as plt
import matplotlib.cm as cm
from matplotlib.patches import Patch
import matplotlib.ticker as ticker
from matplotlib.text import Text
from matplotlib import rcParams

rcParams.update({
    "text.usetex": True,
    "font.family": "serif",
    "text.latex.preamble": r"\usepackage{newtxtext,newtxmath}",
})

def plot_file_size_changes(data):
    for i, d in enumerate(data):
        if d[0].product == 'flac':
            d[0].product = 'libflac'
        data[i] = d
    fontsize = 8

    # Sort data by CVE, then by original size
    products_descending = sorted(set(d[0].product for d in data), reverse=True)
    product_order = {product: i for i, product in enumerate(products_descending)}
    data.sort(key=lambda d: (product_order[d[0].product], d[0].cve, d[1]))

    # Extract unique CVEs in sorted order of appearance
    cves = []
    seen = set()
    for d in data:
        cve = d[0].cve
        if cve not in seen:
            seen.add(cve)
            cves.append(cve)

    # Get tab20 colors, skipping the pair at indices 10 & 11 (6th pair)
    colormap = cm.get_cmap('tab20').colors
    valid_pairs = [
        (colormap[i], colormap[i + 1])
        for i in range(0, len(colormap), 2)
        if i != 10  # skip pair 10 & 11
    ]

    if len(cves) > len(valid_pairs):
        raise ValueError(f"Too many unique CVEs ({len(cves)}), only {len(valid_pairs)} usable color pairs available.")

    cve_to_colors = {
        cve: pair for cve, pair in zip(cves, valid_pairs)
    }

    # Group CVEs by library name (assuming config object has a 'library' attribute)
    # Adjust this attribute name as needed.
    lib_to_cves = {}
    for d in data:
        lib = d[0].product
        cve = d[0].cve
        lib_to_cves.setdefault(lib, set()).add(cve)
    
    # Sort library keys to keep order consistent
    libs_sorted = sorted(lib_to_cves.keys(), key=lambda x: product_order[x])

    # Build legend handles and labels grouped by library
    legend_handles = []
    legend_labels = []

    for lib in libs_sorted:
        # Add library as a dummy text entry (no marker)
        # legend_handles.append(Patch(facecolor='white', edgecolor='white'))  # Invisible block
        # legend_labels.append(lib)
        # Add CVEs for this library
        for cve in sorted(lib_to_cves[lib]):
            color = cve_to_colors[cve][0]
            patch = Patch(color=color, label=cve)
            legend_handles.append(patch)
            legend_labels.append(f'{lib}: {cve}')

    # Prepare data in KiB (bytes / 1024)
    original_sizes_kib = [d[1] / 1024 for d in data]
    size_deltas_kib = [(d[2] - d[1]) / 1024 for d in data]
    cve_labels = [d[0].cve for d in data]
    x = list(range(len(data)))
    bar_width = 0.6  # thinner bars

    fig, ax = plt.subplots(figsize=(3.5, 2.1))
    ax.grid(True, axis='y', linestyle='--', linewidth=0.5, alpha=0.5)
    ax.grid(True, 'minor', axis='y', linestyle='--', linewidth=0.3, alpha=0.4)

    height_cap = 350
    delta_cap_min_height = 5  # Min height to draw visible delta colom
    gap = 10  # Padding above cap for label

    for i, (x_val, orig_kib, delta_kib, cve) in enumerate(zip(x, original_sizes_kib, size_deltas_kib, cve_labels)):
        base_color, extension_color = cve_to_colors[cve]
        total_height = orig_kib + delta_kib
        if total_height <= height_cap:
            ax.bar(x_val, orig_kib, width=bar_width, color=base_color, edgecolor='black', linewidth=0.3)
            ax.bar(x_val, delta_kib, width=bar_width, bottom=orig_kib, color=extension_color, edgecolor='black', linewidth=0.3)
        else:
            base_height = min(orig_kib, height_cap)
            ax.bar(x_val, base_height, width=bar_width, color=base_color, edgecolor='black', linewidth=0.3)

            remaining_space = height_cap - base_height
            delta_shown = max(min(delta_kib, remaining_space), 0)

            if delta_kib > delta_shown:
                cap_height = max(delta_cap_min_height, 2)
                ax.bar(x_val, cap_height, width=bar_width, bottom=height_cap - cap_height,
                       color=extension_color, edgecolor='black', linewidth=0.3)

            cut_extension = 0.75
            cut_y = height_cap * 0.95
            x_left = x_val - bar_width / 2 - cut_extension
            x_right = x_val + bar_width / 2 + cut_extension
            ax.plot([x_left, x_right], [cut_y - 4, cut_y - 1], color='black', linewidth=0.3)
            ax.plot([x_left, x_right], [cut_y + 1, cut_y + 4], color='black', linewidth=0.3)

            # Add vertical label above
            ax.text(x_val - 2, cut_y - 4, f"{int(total_height)} KiB",
                    ha='right', va='center', fontsize=fontsize - 1, color='black')

    ax.tick_params(axis='y', labelsize=fontsize)
    ax.set_ylim(0, height_cap + 10)
    ax.set_xlim(-2 *bar_width, len(data) - 1 + 2 *bar_width)


    # Axis formatting
    ax.set_xlabel('Successful Karonte Patches', fontsize = fontsize)
    ax.set_ylabel('Size (KiB)', fontsize = fontsize)
    ax.set_xticks([])

    # Set y-axis ticks to multiples of 128 KiB
    ax.yaxis.set_major_locator(ticker.MultipleLocator(64))
    ax.yaxis.set_minor_locator(ticker.MultipleLocator(16))

    # Create the legend with grouped labels
    eval_log.info(legend_labels)
    ax.legend(handles=legend_handles, labels=legend_labels, title=None, loc='upper left', handlelength=1.5, handletextpad=0.5, title_fontsize=fontsize+1, fontsize=fontsize)

    plt.tight_layout(pad=1.0)
    plt.savefig("file_size_changes.pdf", format="pdf", bbox_inches='tight', pad_inches=0.007)
    plt.show()

def to_unit(n: int, unit: str) -> int:
    return round(n / {
        'B': 1,
        'KB': 1000,
        'KiB': 1024,
        'MB': 1000 * 1000,
        'MiB': 1024 * 1024,
    }[unit])

def measure_sizes(config: Config):
    global last_binary
    original_size = Path(config.binary_path).stat().st_size
    patched_size = Path(config.output_path).stat().st_size
    patched_binary = lief.parse(config.output_path)
    last_binary = patched_binary
    if not patched_binary:
        eval_log.error(f'patched_binary is None for {config.output_path}')
        exit(1)
    patch_section = patched_binary.get_section('.patch')
    patch_raw_size = 0
    if patch_section:
        patch_raw_size = patch_section.size
        assert patch_raw_size == FIXED_PATCH_SIZE
        patch_blob = patch_section.content.tobytes()
    else:
        patch_blob = None
        for segment in patched_binary.segments:
            blob = segment.content.tobytes()
            if len(blob) == FIXED_PATCH_SIZE:
                patch_raw_size = FIXED_PATCH_SIZE
                patch_blob = blob
                break
        if patch_blob is None:
            eval_log.error('Could not find segment with the correct size. How else would I identify the segment?!?')
            exit(1)
    stripped_size = len(patch_blob.rstrip(b'\x00'))
    improvable_bloat = patch_raw_size - stripped_size
    assert patch_raw_size == FIXED_PATCH_SIZE
    return (config, original_size, patched_size - improvable_bloat)
        # for patched_binary
    # try:
    #     pas
    # except:
    #     import traceback
    #     eval_log.error(traceback.format_exc())
    #     exit(1)

if __name__ == '__main__':
    try:
        eval_log.setLevel(logging.INFO)
        data = json.loads(evaluate_karonte.EVAL_RESULTS_PATH.read_text())
        sizes = list(map(measure_sizes, map(lambda x: Config(**x['cfg']), filter(lambda x: x['result'] == 'SUCCESS', data))))  # pyright:ignore[reportUnknownArgumentType,reportAny,reportUnknownLambdaType]
        # import json
        # Path('test-output-data.json').write_bytes(json.dumps(sizes))
        # print(list(filter(lambda x: x[1] > 700, map(lambda x: [asdict(x[0]), to_unit(x[1], "KiB"), to_unit(x[2], "KiB")],sizes))))
        plot_file_size_changes(sizes)
    except:
        import traceback
        eval_log.error(traceback.format_exc())
        exit(1)
