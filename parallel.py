
import multiprocessing
from multiprocessing.pool import ApplyResult

from tqdm import tqdm
from patch_karonte import JobResult, karonte_job
from patching.configuration import Config
import time

def _work(cfg: Config) -> tuple[Config, JobResult]:
    result = karonte_job(cfg)
    return (cfg, result)

def patch_and_test_parallely(cfgs: list[Config]) -> list[tuple[Config, JobResult]]:
    results: list[tuple[Config, JobResult]] = []
    with multiprocessing.Pool() as pool:
        busy_files: set[str] = set()
        pending_jobs = cfgs
        async_results: list[ApplyResult[tuple[Config, JobResult]]] = []

        with tqdm(total=len(cfgs)) as progress:
            while pending_jobs or async_results:
                for res in async_results[:]:
                    if res.ready():
                        cfg, result = res.get()
                        busy_files.discard(cfg.binary_path)
                        async_results.remove(res)
                        results.append((cfg, result))
                        _ = progress.update(1)

                # Assign eligible jobs
                i = 0
                while i < len(pending_jobs):
                    cfg = pending_jobs[i]
                    if cfg.binary_path not in busy_files:
                        busy_files.add(cfg.product)
                        result = pool.apply_async(_work, args=(cfg,))
                        async_results.append(result)
                        _ = pending_jobs.pop(i)
                    else:
                        i += 1

                time.sleep(0.1)
    return results

