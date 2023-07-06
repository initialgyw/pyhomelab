'''pyhomelab/shell.py'''
import logging
import subprocess
import shlex
import pyhomelab.exceptions

class ShellException(pyhomelab.exceptions.PyHomelabException):
    '''pyHomelab Shell Exception'''


class Shell:
    '''Do things in Shell'''

    # https://stackoverflow.com/questions/37340049/how-do-i-print-colored-output-to-the-terminal-in-python
    TERMCOLORS = {
        'RED': '\033[1;31m',
        'BLUE': '\033[1;34m',
        'CYAN': '\033[1;36m',
        'GREEN': '\033[0;32m',
        'RESET': '\033[0;0m',
        'BOLD': '\033[;1m',
        'REVERSE': '\033[;7m'
    }

    @staticmethod
    def run_shell_cmd(cmd: str,
                      log: logging.Logger,
                      noop: bool = False,
                      sensitive_str: str = None,
                      raise_error: bool = False) -> subprocess.CompletedProcess | None:
        '''Run any shell command
        
        Parameters
        ----------
        cmd : str, required
            commands to run
        log : logging.Logger
        noop : bool
            Just print command instead of running it, default = False
        sensitive_str : str
            Replace a sensitive string in cmd
        raise_error : bool
            enable check on subprocess.run

        Returns
        -------
        subprocess.CompletedProcess
            CompletedProcess(args=[],
                             returncode=1,
                             stdout='')

        Raises
        ------
        subprocess.CalledProcessError
            if raise_error is True and command returned a non-zero.
        '''

        # create a variable just for logging
        if sensitive_str is not None:
            log_cmd = cmd.replace(cmd, sensitive_str)
        else:
            log_cmd = cmd

        if noop is True:
            log.noop("RUNNING: %s", log_cmd)
            return None
        log.debug("RUNNING: %s", cmd)

        result = subprocess.run(shlex.split(cmd),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                                check=raise_error)

        return result
