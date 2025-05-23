import logging
from typing import override

eval_log: logging.Logger = logging.getLogger('Evaluation')
patch_log: logging.Logger = logging.getLogger('Patching')
test_log: logging.Logger = logging.getLogger('Testing')
test_result_log: logging.Logger = logging.getLogger('TestResult')

class LevelFilter(logging.Filter):
    def __init__(self, level: int) -> None:
        super().__init__()
        self.level: int = level

    @override
    def filter(self, record: logging.LogRecord):
        return record.levelno == self.level

for purpose, logger in {'patch': patch_log, 'test': test_log, 'result': test_result_log}.items():
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    for level_str, level in logging.getLevelNamesMapping().items():
        handler = logging.FileHandler(f'{purpose}-{level_str}.log')
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        handler.addFilter(LevelFilter(level))
        logger.addHandler(handler)

def mute_other_loggers() -> None:
    def disable_logger(name: str):
        logging.getLogger(name).disabled = True
    disable_logger('cle.loader')
    disable_logger('cle.backends.externs')
    disable_logger('claripy.frontends.light_frontend')
    disable_logger('patcherex.backends.DetourBackend')
    disable_logger('pyvex.lifting.gym.arm_spotter')
    disable_logger('angr.state_plugins.unicorn_engine')
    disable_logger('cle.backends.elf.elf')
    disable_logger('cle.backends.tls.tls_object')

    import lief
    lief.logging.disable()

