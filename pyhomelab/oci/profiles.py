'''pyhomelab/oci/profiles.py

Different profile objects that can be used to authenticate with the OCIWrapper Class
'''
import pathlib
import configparser
import subprocess
import dataclasses
from pyhomelab.logger import logger
from pyhomelab.shell import Shell


@dataclasses.dataclass
class OCIBrowserAuthProfile:
    '''Object to store Browser config auth
    
    Parameters
    ----------
    name : str
        name of the profile, required
    region : str
        primary region of the account
    config_file : str | pathlib.PosixPath
        location of the config_file, default = ~/.oci/config
    log_level : str,
        log level of this class, default = DEBUG
    log_file : str,
        log file location
    '''
    name: str
    region: str
    config_file: str | pathlib.PosixPath = pathlib.Path('~/.oci/config').expanduser()
    tenancy: str = None
    log_level: str = 'DEBUG'
    log_file: str = None

    def __post_init__(self) -> None:
        self.log = logger(name='OCIBrowserAuthConfigProfile',
                          log_level=self.log_level,
                          log_file=self.log_file)

        if isinstance(self.config_file, str):
            self.config_file = pathlib.Path(self.config_file).expanduser()
            self.log.trace('Converted %s to pathlib object', self.config_file)

        # validate session
        if self.validate_session() is False or self.validate_region() is False:
            self.browser_authenticate()

    def browser_authenticate(self) -> None:
        '''Open up browser to authenticate
        
        Raises
        ------
        subprocess.CalledProcessError
            if authentication fails
        '''
        # create parent directory of the config file
        if self.config_file.parent.is_dir() is False:
            self.log.trace("%s does not exists. Creating.", self.config_file.parent)
            self.config_file.parent.mkdir(parents=True, mode=0o755)

        cmd = (f"oci session authenticate --config-location {self.config_file} "
               f"--region {self.region} --profile-name {self.name}")
        if self.tenancy is not None:
            cmd = cmd + f" --tenancy-name {self.tenancy}"

        Shell.run_shell_cmd(cmd=cmd, log=self.log, raise_error=True)

        self.log.debug('Session is authenticated.')

    def validate_session(self) -> bool:
        '''Validate a security_token session'''

        cmd = (f"oci session validate --config-file {self.config_file} "
               f"--profile {self.name} --local")

        try:
            Shell.run_shell_cmd(cmd=cmd, log=self.log, raise_error=True)
        except subprocess.CalledProcessError:
            self.log.warning('Current session is not valid')
            return False

        self.log.debug('Current Session is valid')
        return True

    def validate_region(self) -> bool:
        '''Validate Region
        
        Raises
        ------
        oci.exceptions.ProfileNotFound
        '''

        # read config
        configs = configparser.ConfigParser()
        configs.read(self.config_file)

        try:
            if configs[self.name]['region'] != self.region:
                self.log.error("Region does not match: %s (input) vs %s (in config-file)",
                               self.region, configs[self.name]['region'])
                return False
        except KeyError as err:
            self.log.warning(err)
            return False

        self.log.trace("Region provided matches region in %s config file", self.config_file)
        return True


@dataclasses.dataclass
class OCIAPIConfigProfile:
    '''Object to store API config profile'''
    name: str
    config_file: str
    log_level: str = 'DEBUG'
    log_file: str = None

    def __post_init__(self):
        self.log = logger(name='OCIAPIConfigProfile',
                          log_level=self.log_level,
                          log_file=self.log_file)

        if isinstance(self.config_file, str):
            self.config_file = pathlib.Path(self.config_file).expanduser()

@dataclasses.dataclass
class OCIAPIProfile:
    '''Object to store API profile'''
    user: str
    region: str
    tenancy: str
    fingerprint: str
    key: str | pathlib.PosixPath
    key_passphrase: str = None
    log_level: str = 'DEBUG'
    log_file: str = None

    def __post_init__(self):
        self.log = logger(name='OCIAPIConfig', log_level=self.log_level, log_file=self.log_file)

        if pathlib.Path(self.key).expanduser().exists() is True:
            self.log.trace(f"{self.key} is a file, so setting it as key_file")
            self.key_file: str = self.key
        else:
            self.log.trace('Provided key is not a file, so setting it as key_content')
            self.key_content: str = self.key

    def as_dict(self) -> dict[str, str]:
        '''Return variables for profile as dict'''
        config = {
            'user': self.user,
            'region': self.region,
            'tenancy': self.tenancy,
            'fingerprint': self.fingerprint
        }
        if self.key_file:
            config['key_file'] = self.key_file
        elif self.key_content:
            config['key_content'] = self.key_content

        return config

    def write_config(self, config_file: pathlib.PosixPath, section: str) -> None:
        '''Write config to config file'''
        update_config_file: bool = False
        config_file.parent.mkdir(parents=True, exist_ok=True)

        configs = configparser.ConfigParser()
        configs.read(config_file)

        if section in configs.sections():
            for key, value in self.as_dict().items():
                try:
                    if configs[section][key] != value:
                        self.log.debug("%s in %s does not match. Will update.", key, config_file)
                        configs[section][key] = value
                        update_config_file = True
                except KeyError:
                    self.log.debug("%s does not exist under %s in %s. Will update.",
                                   key, section, config_file)
                    configs[section][key] = value
                    update_config_file = True

            for key in configs[section].keys():
                if key not in self.as_dict():
                    self.log.debug("%s should not be in %s[%s]. Deleting.",
                                   key, config_file, section)
                    del configs[section][key]
                    update_config_file = True
        else:
            configs[section] = self.as_dict()
            update_config_file = True

        if update_config_file is True:
            self.log.trace("Updating %s.", config_file)
            with open(config_file, 'w', encoding='utf-8') as file:
                configs.write(file)
        else:
            self.log.trace("%s already contains %s. Update not needed.", config_file, section)
