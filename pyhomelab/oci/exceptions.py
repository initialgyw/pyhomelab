'''pyhomelab/oci/exceptions.py'''
import oci
from pyhomelab.exceptions import PyHomelabException

def extract_detail(error: oci.exceptions.ServiceError):
    '''Extract detail from OCI error'''
    error_msg = [msg for msg in error.message.split(',') if '"detail":' in msg][0]
    error_msg = error_msg.split(':')[1].replace('"', '')

    return error_msg

class OCIWrapperException(PyHomelabException):
    '''Storing OCI Wrapper Exception'''

class OCIAuthenticateError(oci.exceptions.ClientError):
    '''Failed to authenticate'''

class OCISecurityTokenSessionExpired(oci.exceptions.ClientError):
    '''Security token expired'''

class OCIUserCreationError(OCIWrapperException):
    '''OCI User Creation Error'''

    def __init__(self, error: oci.exceptions.ServiceError) -> None:
        error_msg = extract_detail(error)
        super().__init__(error_msg)

class OCIUserUpdateFailed(OCIWrapperException):
    '''OCIUserUpdateFailed'''

class OCINoCustomerSecretKeyFound(OCIWrapperException):
    '''No Customer Secret Key Found'''

class OCICustomerSecretKeyCreationFail(OCIWrapperException):
    '''Unable to create Customer Secret Key'''

class OCIAPIKeyNotFound(OCIWrapperException):
    '''No API key found'''

class OCIAPIKeyUploadFailed(OCIWrapperException):
    '''OCIAPIKeyUploadFailed'''

    def __init__(self, error: oci.exceptions.ServiceError) -> None:
        error_msg = extract_detail(error)
        super().__init__(error_msg)

class OCIVaultNotActive(OCIWrapperException):
    '''Vault not active'''

class OCISecretVersionDeletionFailed(OCIWrapperException):
    '''OCISecretVersionDeletionFailed'''

class OCISecretDecryptionFailed(OCIWrapperException):
    '''OCISecretBase64DecryptionError'''

class OCISecretDoesNotExist(OCIWrapperException):
    '''OCISecretDoesNotExist'''

class OCISecretDeletionFailed(OCIWrapperException):
    '''OCISecretDeletionFailed'''

class OCISecretUpdateFailed(OCIWrapperException):
    '''OCISecretUpdateFailed'''
