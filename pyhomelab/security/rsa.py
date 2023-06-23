'''pyhomelab/security/rsa.py'''
import hashlib
import os
import stat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class RSAException(Exception):
    '''RSA Exceptiom'''

class FileNotPEMFormat(RSAException):
    '''FileNotPEMFormat'''

class WrongPassword(RSAException):
    '''WrongPassword'''

class RSAWrapper:
    '''RSA Wrapper'''

    def __init__(self) -> None:
        pass

    @staticmethod
    def generate_private_key(output_file: str,
                             key_size=4096,
                             passphrase: str = None
    ) -> rsa.RSAPrivateKey:
        '''Generate RSA private key
        
        Parameters
        ----------
        output_file: str, required
            Where to save the PEM format private key
        key_size: int
        passphrase: str
            if provided, it will encrypt the key
        
        Returns
        -------
        rsa.RSAPrivateKey
        '''

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        private_bytes = {
            'encoding': serialization.Encoding.PEM
        }

        if passphrase is None:
            private_bytes['format'] = serialization.PrivateFormat.TraditionalOpenSSL
            private_bytes['encryption_algorithm'] = serialization.NoEncryption()
        else:
            private_bytes['format'] = serialization.PrivateFormat.PKCS8
            private_bytes['encryption_algorithm'] = serialization.BestAvailableEncryption(
                                                                    bytes(passphrase, 'utf-8'))

        # write private out in PEM format
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(private_key.private_bytes(**private_bytes).decode())

        # updating permission for user rw only
        os.chmod(output_file, stat.S_IREAD | stat.S_IWRITE)

        return private_key

    @staticmethod
    def load_private_pem_key(pem_file: str, passphrase: str = None) -> rsa.RSAPrivateKey:
        '''Load PEM private key

        Parameters
        ----------
        pem_file: str, required
            location of the PEM private key
        passphrase: str

        Returns
        -------
        rsa.PrivateKey

        Raises
        ------
        FileNotPEMFormat
        WrongPassword
        '''

        with open(pem_file, 'rb') as file:
            load_params = {
                'data': file.read(),
                'backend': default_backend()
            }

        if passphrase is not None:
            load_params['password'] = bytes(passphrase, 'utf-8')
        else:
            load_params['password'] = None

        try:
            private_key = serialization.load_pem_private_key(**load_params)
        except ValueError as err:
            if 'Could not deserialize key data' in str(err):
                raise FileNotPEMFormat(err) from err
            elif 'Bad decrypt. Incorrect password' in str(err):
                raise WrongPassword(err) from err
            else:
                raise
        except TypeError as err:
            if 'Password was not given but private key is encrypted' in str(err):
                raise WrongPassword(err) from err
            else:
                raise

        return private_key

    @staticmethod
    def generate_public_pem_key(private_key: rsa.RSAPrivateKey,
                                output_file: str = None):
        '''
        
        Raises
        ------
        NotImplementedError
        '''
        public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)

        if output_file is not None:
            with open(output_file, 'w', encoding='utf-8') as file:
                file.write(public_key.decode())

        return public_key

    @staticmethod
    def convert_pem_to_der(private_key: rsa.RSAPrivateKey) -> bytes:
        '''Convert a private PEM to DER
        
        Parameters
        ----------
        private_key : rsa.RSAPrivateKey

        Returns
        -------
        bytes
        '''
        return private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)

    @staticmethod
    def get_der_md5(der: bytes) -> str:
        '''Get MD5 of the DER
        
        Parameters
        ----------
        der : bytes
            key in DER format
        
        Returns
        -------
        str
            aa:bb:cc:ff...
        '''
        md5 = hashlib.md5(der).hexdigest()
        return ':'.join(a + b for a, b in zip(md5[::2], md5[1::2]))
