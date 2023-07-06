'''pyhomelab/helper.py'''
import base64
import binascii

class Helper:
    '''Bunch of Helper functions
    
    Methods
    -------
    isBase
    '''

    def __init__(self) -> None:
        pass

    @staticmethod
    def is_base64_encoded(value: str | bytes) -> bool:
        '''Check if the input provided is a base64 encoded
        
        Parameters
        ----------
        value : str | bytes
            the value to check

        Returns
        -------
        bool

        Raises
        ------
        ValueError
            if input is not a string or bytes
        '''
        if isinstance(value, str) is True:
            try:
                value_byte = bytes(value, 'ascii')
            except UnicodeEncodeError:
                return False
        elif isinstance(value, bytes):
            value_byte = value
        else:
            raise ValueError('Value must be a string or bytes')

        try:
            return base64.b64encode(base64.b64decode(value_byte)) == value_byte
        except binascii.Error:
            return False
