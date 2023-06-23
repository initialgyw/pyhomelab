'''pyhomelab/logger.py'''
import logging
import pathlib
import time
import functools

# this stores all the loggers
loggers: dict = {}

# add additional log level
logging.TRACE = 5
logging.addLevelName(logging.TRACE, 'TRACE')
logging.Logger.trace = functools.partialmethod(logging.Logger.log, logging.TRACE)
logging.trace = functools.partial(logging.log, logging.TRACE)

logging.SUCCESS = 35
logging.addLevelName(logging.SUCCESS, 'SUCCESS')
logging.Logger.success = functools.partialmethod(logging.Logger.log, logging.SUCCESS)
logging.success = functools.partial(logging.log, logging.SUCCESS)

logging.NOOP = 60
logging.addLevelName(logging.NOOP, 'NOOP')
logging.Logger.noop = functools.partialmethod(logging.Logger.log, logging.NOOP)
logging.noop = functools.partial(logging.log, logging.NOOP)

log_levels = {
    'TRACE': logging.TRACE,
    4: logging.TRACE,
    'DEBUG': logging.DEBUG,
    3: logging.DEBUG,
    'INFO': logging.INFO,
    2: logging.INFO,
    'WARNING': logging.WARNING,
    1: logging.WARNING,
    'SUCCESS': logging.SUCCESS,
    'ERROR': logging.ERROR,
    0: logging.ERROR,
}

def logger(name: str = __name__,
           log_console: bool = True,
           log_file: str = None,
           log_level: int | str = 'DEBUG'
) -> logging.Logger:
    '''A logging function that can be imported for use

    Parameters
    ----------
    name: str, defaults = __name__
    log_console : bool, default = True
        enabling logging to console
    log_file: str, defaults = None
        Absolute path of the file to log to. If None is provided, then it won't log to file
    log_leve: Union[int, str], defaults to Debug
        https://docs.python.org/3/library/logging.html#logging-levels

    Returns
    -------
    logging.logger

    Examples
    --------
    >>>> from sysops.logger import logger
    >>>> log = log(name='SCRIPT', log_level='DEBUG')
    >>>> log.trace('TRACE')
    >>>> log.debug('DEBUG')
    >>>> log.info('INFO')
    >>>> log.warning('WARNING')
    >>>> log.success('SUCCESS')
    >>>> log.error('ERROR')
    >>>> log.critical('CRITICAL')
    '''

    # If logger already exist
    if loggers.get(name):
        return loggers.get(name)

    # logformatter
    logging.Formatter.converter = time.gmtime
    log_formatter = logging.Formatter(fmt=("{ time: %(asctime)s, "
                                           "level: %(levelname)s, "
                                           "name: %(name)s, "
                                           "func_name: %(funcName)s, "
                                           "message: \"%(message)s\" }"))

    # set logging
    log = logging.getLogger(name)

    # ensure log_level passed in is converted to uppercase, if int - ignore
    try:
        log_level = log_level.upper()
    except AttributeError:
        # that means int was pass in and it needs to be 4 or less
        log_level = min(log_level, 4)

    # set log level
    try:
        log.setLevel(log_levels[log_level])
    except KeyError:
        log.setLevel(logging.DEBUG)

    # set filehandler
    if log_file is not None:
        if not log_file.endswith('.log'):
            log_file = f"{log_file}.log"
        log_file = pathlib.Path(log_file).expanduser()
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(log_formatter)
        log.addHandler(file_handler)

    # set console logging
    if log_console is True:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        log.addHandler(console_handler)

    # add it into the global logging
    loggers[name] = log

    return log
