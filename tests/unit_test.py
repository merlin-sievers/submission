from pathlib import Path
import subprocess

from helpers import CVEFunctionInfo, get_sysroot
from log import test_log, test_result_log
from patching.configuration import Config

class UnitTest:
    EVALUATE_CMD: str = NotImplemented

    def __init__(self, config: Config):
        self.config: Config = config
        self.cves: dict[str, CVEFunctionInfo] = {}


    @property
    def ldprefix(self) -> Path:
        return get_sysroot(Path(self.config.firmware))

    def unit_test_patch(self) -> bool:
        raise NotImplementedError

    def run_command(self, command: str, cwd: str):
        
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, cwd=cwd)
        except subprocess.CalledProcessError as e:
            test_log.error(f'{self.config.product}: Command "{command}" failed with error: {e} in %s of %s', self.config.test_dir, self.config.output_path)
            return False

        if result.returncode != 0:
            test_log.error(f'Failed to run "{command}" in "{cwd}"')
            return False
        return True

    def evaluate_results(self) -> bool:
        cwd = self.config.test_dir

        result = subprocess.run(self.EVALUATE_CMD, shell=True, capture_output=True, cwd=cwd)
        
        if result.returncode == 0:
            test_result_log.error(f"{self.config.product}: Unit test of {self.config.output_path} failed in {self.config.firmware}")
            return False
        elif result.returncode == 1:
            test_result_log.info(f"{self.config.product}: Unit test of {self.config.output_path} passed in {self.config.firmware}")
            return True
        else:
            test_result_log.error(f"{self.config.product}: Unknown error occurred while evaluating results for {self.config.output_path}")
            return False

