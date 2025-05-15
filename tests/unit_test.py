import logging
import subprocess



class UnitTest:
    def __init__(self, config):
        self.config = config


    def unit_test_patch(self):
        return NotImplementedError

    def run_command(self, command, cwd):
        
        command_error_logger = logging.getLogger('command_error-'+self.config.product+'.log')
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, cwd=cwd)
        except subprocess.CalledProcessError as e:
            command_error_logger.error(f'Command "{command}" failed with error: {e} in %s of %s', self.config.test_dir, self.config.output_path)
            return False

        if result.returncode != 0:
            command_error_logger.error(f'Failed to run "{command}" in "{cwd}"')
            return False
        return True

    def evaluate_results(self):
        return NotImplementedError
