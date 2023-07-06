'''pyhomelab/oci/__init__.py'''
import copy
import pathlib
import base64
import datetime as dt
import time
import oci
from pyhomelab.oci.profiles import (OCIBrowserAuthProfile,
                                    OCIAPIConfigProfile,
                                    OCIAPIProfile)
import pyhomelab.oci.exceptions
from pyhomelab.security.rsa import RSAWrapper
from pyhomelab.helper import Helper


class OCIWrapper:
    '''OCI Wrapper
    
    Parameters
    ----------
    log_level : str
        set the log_level for this class
    log_file : str
        if defined, log to this file

    Attributes
    ----------
    log : logging.Logger
        logging object
    config : dict[str, str]
        configs
    auth : dict[str, str]
        auth configs
    identity_clients : oci.identity.IdentityClient
        identity_client
    kms_vault_client : oci.key_management.KmsVaultClient
        kms_vault_client
    vault_client : oci.vault.VaultsClient
        vault_client
    secrets_client : oci.secrets.SecretsClient
        secrets client

    Methods
    -------
    set_freeform_tags
    create_user
    update_user_capabilities
    upload_api_key
    create_group
    add_user_to_group
    get_compartment
    create_compartment
    create_policy
    get_vaults
    create_vault
    create_vault_key
    vault_list_secrets
    vault_get_secret
    vault_delete_secret_version
    vault_set_secret
    vault_delete_secret
    '''
    def __init__(self,
                 profile: OCIBrowserAuthProfile | OCIAPIConfigProfile | OCIAPIProfile
    ) -> None:
        self.log = profile.log
        self.log.name = 'OCIWrapper'

        # initial variables
        signer = None

        # configure config for auth
        if isinstance(profile, OCIAPIProfile):
            self.config = {
                'user': profile.user_id,
                'fingerprint': profile.fingerprint,
                'tenancy': profile.tenancy,
                'region': profile.region
            }

            try:
                self.config['key_file'] = profile.key_file
            except AttributeError:
                self.config['key_content'] = profile.key_content

            # validate the config
            if oci.config.validate_config(self.config) is False:
                raise oci.exceptions.InvalidConfig(f"Configs provided is invalid: {profile}")

        else:
            self.config = oci.config.from_file(file_location=profile.config_file,
                                               profile_name=profile.name)

        # enable verbose logging in config
        if profile.log_level in ['TRACE']:
            self.config['log_requests'] = True

        # if security_token detected, then signer is needed
        if 'security_token_file' in self.config:
            token = None

            with open(self.config['security_token_file'], 'r', encoding='utf-8') as file:
                token = file.read()

            signer = oci.auth.signers.SecurityTokenSigner(
                        token=token,
                        private_key=oci.signer.load_private_key_from_file(
                                        self.config['key_file']))

        # configuring auth parameters
        self.auth = {'config': self.config}
        if signer is not None:
            self.auth['signer'] = signer

        # configuring oci clients
        self.identity_client = oci.identity.IdentityClient(**self.auth)
        self.kms_vault_client = oci.key_management.KmsVaultClient(**self.auth)
        self.vault_client = oci.vault.VaultsClient(**self.auth)
        self.secrets_client = oci.secrets.SecretsClient(**self.auth)

        self.log.debug('OCIWrapper initialized.')

    def set_freeform_tags(self,
                          existing_tags: dict[str, str],
                          set_tags: dict[str, str]
    ) -> dict[str, str]:
        '''Combine freeform tags
        
        Parameters
        ----------
        existing_tags : dict[str, str]
            tags that already exists on the resource
        set_tags : dict[str, str]
            tags you want to include
        
        Returns
        -------
        dict[str, str]
            combine tags if set_tags not in existing_tags
        '''

        combine_tags = {}
        for key, value in set_tags.items():
            if key not in existing_tags or value != existing_tags[key]:
                combine_tags = {**existing_tags, **set_tags}
                break

        return combine_tags

    def create_user(self,
                    name: str,
                    description: str,
                    email: str = None,
                    freeform_tags: dict[str, str] = None,
                    capabilities: dict[str, bool] = None
    ) -> oci.identity.models.user.User:
        '''Create/Update user
        
        Parameters
        ----------
        name: str, required
            username
        description: str, required
            description for user
        email: str
            required if domain is migrated, default = None
        freeform_tags: dict[str, str]
            add tags to user, default = None

        Returns
        -------
        oci.identity.models.user.User

        Raises
        ------
        pyhomelab.oci.exceptions.OCIUserCreationError
        '''

        create_user_details = oci.identity.models.CreateUserDetails(
                                compartment_id=self.config['tenancy'],
                                name=name,
                                email=email,
                                description=description,
                                freeform_tags=freeform_tags)

        # create user
        try:
            user = self.identity_client.create_user(create_user_details=create_user_details).data
        except oci.exceptions.ServiceError as err:
            # if user already exists, then search for that user
            if 'User with the same userName already exists' in str(err):
                self.log.warning("%s user already exists", name)
                user = self.identity_client.list_users(compartment_id=self.config['tenancy'],
                                                       name=name).data[0]
            else:
                raise pyhomelab.oci.exceptions.OCIUserCreationError(err) from err
        else:
            self.log.success("%s user created.", user.name)

            # updating capabilities
            user = self.update_user_capabilities(user=user,
                                                 capabilities=capabilities,
                                                 set_default=True)
            return user

        # If user is already created, the update user info if necessary
        update_user_details = {}
        if user.description != description:
            self.log.trace("Updating %s description from \"%s\" to \"%s\"",
                           user.name, user.description, description)
            update_user_details['description'] = description

        # check email
        if user.email != email:
            self.log.trace("Updating %s email from %s to %s", user.name, user.email, email)
            update_user_details['email'] = email

        # check freeform tags
        if bool(freeform_tags) is True:
            update_tags = self.set_freeform_tags(existing_tags=user.freeform_tags,
                                                 set_tags=freeform_tags)
            if bool(update_tags) is True:
                update_user_details['freeform_tags'] = {**user.freeform_tags, **freeform_tags}
                self.log.debug("Merging %s freeform tags from %s to %s",
                               user.name,
                               user.freeform_tags,
                               update_user_details['freeform_tags'])

        if bool(update_user_details) is True:
            self.log.debug("Updating %s with %s", user.name, update_user_details)
            update_user_details = oci.identity.models.UpdateUserDetails(**update_user_details)
            user = self.identity_client.update_user(user_id=user.id,
                                                    update_user_details=update_user_details).data
            self.log.success("%s user updated.", user.name)

        user = self.update_user_capabilities(user=user,
                                             capabilities=capabilities,
                                             set_default=False)

        return user

    def update_user_capabilities(self,
                                 user: oci.identity.models.user.User | str,
                                 capabilities: dict[str, str] = None,
                                 set_default: bool = False) -> oci.identity.models.user.User:
        '''Update user capabilities
        
        Parameters
        ----------
        user: oci.identity.models.user.User | str
            if str is passed in, it'll look for that user
        capabilities : dict[str, str]

        Returns
        -------
        oci.identity.models.user.User

        Raises
        ------
        ValueError
            bad user input
        pyhomelab.oci.exceptions.OCIUserUpdateFailed
            bad capabilities input
        '''

        default_capabilities = {
            'can_use_api_keys': False,
            'can_use_auth_tokens': False,
            'can_use_console_password': False,
            'can_use_customer_secret_keys': False,
            'can_use_db_credentials': False,
            'can_use_o_auth2_client_credentials': False,
            'can_use_smtp_credentials': False
        }

        # variable validation
        if capabilities is None:
            capabilities = default_capabilities
        else:
            if set_default is True:
                capabilities = {**default_capabilities, **capabilities}

        if isinstance(user, str):
            self.log.trace("Getting user data for %s", user)
            user = self.identity_client.get_user(user_id=user).data
            self.log.trace("User %s = %s", user.id, user.name)
        elif isinstance(user, oci.identity.models.user.User) is False:
            raise ValueError('User input is not valid type.')

        # check if capabilities needs updating
        capabilities_update = {}
        for cap, val in capabilities.items():
            try:
                if user.capabilities.__dict__[f"_{cap}"] != val:
                    capabilities_update[cap] = val
            except KeyError as err:
                raise pyhomelab.oci.exceptions.OCIUserUpdateFailed(
                    f"User capability {cap} does not exist.") from err

        if bool(capabilities_update) is False:
            self.log.debug("No need to update user %s capabilities", user.name)
            return user

        # update capabilities
        user = self.identity_client.update_user_capabilities(
                user_id=user.id,
                update_user_capabilities_details=oci.identity.models.UpdateUserCapabilitiesDetails(
                                                    **capabilities_update)).data
        self.log.success("User %s capabilities updated with %s", user.name, user.capabilities)

        return user

    def upload_api_key(self,
                       user: oci.identity.models.user.User,
                       key_file: pathlib.PosixPath,
                       key_passphrase: str = None) -> str:
        '''Upload API key to user
        
        Parameters
        ----------
        user : oci.identity.models.user.User

        public_key_file : str
            location of the public key file in PEM format

        Returns
        -------
        str
            key fingerprint

        Raises
        ------
        pyhomelab.oci.exceptions.OCIAPIKeyUploadFailed
        '''

        # load key file or generate the private key and save to key file
        try:
            private_key = RSAWrapper.load_private_pem_key(pem_file=key_file,
                                                          passphrase=key_passphrase)
            self.log.trace("%s key loaded.", key_file)
        except FileNotFoundError:
            private_key = RSAWrapper.generate_private_key(output_file=key_file,
                                                          passphrase=key_passphrase)
            self.log.success("Created a RSA key and saved it to %s", key_file)

        # get the der and md5 of der
        key_der = RSAWrapper.convert_pem_to_der(private_key=private_key)
        key_fingerprint = RSAWrapper.get_der_md5(der=key_der)
        self.log.trace("%s key fingerprint = %s", key_file, key_fingerprint)

        # create the public key
        public_key = RSAWrapper.generate_public_pem_key(private_key=private_key)

        # upload the public key
        create_api_key_details = oci.identity.models.CreateApiKeyDetails(key=public_key.decode())
        try:
            _ = self.identity_client.upload_api_key(
                    user_id=user.id,
                    create_api_key_details=create_api_key_details).data
        except oci.exceptions.ServiceError as err:
            if 'already exists' in str(err.message):
                self.log.info("User %s already using %s", user.name, key_file)
                return key_fingerprint
            raise pyhomelab.oci.exceptions.OCIAPIKeyUploadFailed(err) from err
        self.log.success(f"{key_file} uploaded for {user.name}")

        return key_fingerprint

    def create_group(self,
                     name: str,
                     description: str,
                     freeform_tags: dict[str, str] = None
    ) -> oci.identity.models.group.Group:
        '''Create a group

        Parameters
        ----------
        name : str, required
            name of the group
        description : str, required
            group description
        freeform_tags: dict[str, str]
            Tags to include when creating group

        Returns
        -------
        oci.identity.models.group.Group
            {"compartment_id": "ocid1.tenancy.oc1..",
             "defined_tags": {},
             "description": "Administrators",
             "freeform_tags": {},
             "id": "ocid1.group.oc1..aaaaaaaahqniiqf25s64plzvxzgbfklvuqgnit3fejzwx6c7e6inq4bpbx7q",
             "inactive_status": null,
             "lifecycle_state": "ACTIVE",
             "name": "Administrators",
             "time_created": "2022-02-13T22:39:49.922000+00:00"}
        '''

        create_group_details = oci.identity.models.CreateGroupDetails(
                                                    compartment_id=self.config['tenancy'],
                                                    name=name,
                                                    description=description,
                                                    freeform_tags=freeform_tags)

        try:
            group = self.identity_client.create_group(
                                            create_group_details=create_group_details).data
        except oci.exceptions.ServiceError as err:
            if 'Group with the same displayName already exists' in str(err.message):
                self.log.warning("Group %s already exists.", name)
                group = self.identity_client.list_groups(compartment_id=self.config['tenancy'],
                                                         name=name).data[0]
            else:
                raise
        else:
            self.log.success("Group %s created.", group.name)
            return group

        update_group_details = {}

        # check description
        if group.description != description:
            update_group_details['description'] = description

        # update freeform tags
        if bool(freeform_tags) is True:
            update_tags = self.set_freeform_tags(existing_tags=group.freeform_tags,
                                                 set_tags=freeform_tags)
            if bool(update_tags) is True:
                update_group_details['freeform_tags'] = update_tags

        if bool(update_group_details) is True:
            self.log.debug("Updating group %s with %s", group.name, str(update_group_details))
            update_group_details = oci.identity.models.UpdateGroupDetails(**update_group_details)
            group = self.identity_client.update_group(
                                            group_id=group.id,
                                            update_group_details=update_group_details).data

        return group

    def add_user_to_group(self,
                          group: oci.identity.models.group.Group,
                          user: oci.identity.models.user.User
    ) -> oci.identity.models.user_group_membership.UserGroupMembership:
        '''Add User to group

        Parameters
        ----------
        group : oci.identity.models.group.Group
            group for user to add to
        user : oci.identity.models.user.User
            user to add group to
        
        Returns
        -------
        oci.identity.models.user_group_membership.UserGroupMembership
            {
             "compartment_id": "ocid1.tenancy.oc1..<REDACTED>",
             "group_id": "ocid1.group.oc1..<REDACTED>",
             "id": "ocid1.groupmembership.oc1..<REDACTED>",
             "inactive_status": null,
             "lifecycle_state": "ACTIVE",
             "time_created": "2023-06-16T01:35:40.852000+00:00",
             "user_id": "ocid1.user.oc1..<REDACTED>"
            }

        Raises
        ------
        oci.exceptions.ServiceError
        '''

        add_user_to_group_details = oci.identity.models.AddUserToGroupDetails(user_id=user.id,
                                                                              group_id=group.id)
        # add user to group
        try:
            group_membership = self.identity_client.add_user_to_group(
                                            add_user_to_group_details=add_user_to_group_details)
        except oci.exceptions.ServiceError as err:
            if 'You cannot create a Group with duplicate members' in str(err.message):
                self.log.warning("User %s is already in group %s", user.name, group.name)
                group_membership = self.identity_client.list_user_group_memberships(
                                                            compartment_id=self.config['tenancy'],
                                                            group_id=group.id,
                                                            user_id=user.id).data[0]
                return group_membership
            raise

        self.log.success(f"Added {user.name} to group {group.name}")
        return group_membership

    def get_compartments(
            self,
            name: str = None
    ) -> list[oci.identity.models.compartment.Compartment]:
        '''Get compartment

        Parameters
        ----------
        name : str
            name of the compartment to search for

        Returns
        -------
        list[oci.identity.models.compartment.Compartment]
        '''

        compartment_search = {
            'compartment_id': self.config['tenancy'],
            'compartment_id_in_subtree': True,
        }

        try:
            compartments = self.identity_client.list_compartments(**compartment_search).data
        except oci.exceptions.ServiceError as err:
            if err.code == 'NotAuthenticated':
                raise pyhomelab.oci.exceptions.OCIAuthenticateError(err.message)

        self.log.trace("%i compartments found", len(compartments))
        compartments = [c for c in compartments if c.lifecycle_state in ['CREATING', 'ACTIVE']]
        self.log.trace("%i compartments found that are active", len(compartments))

        if name is None:
            return compartments

        compartments = [c for c in compartments if c.name == name]
        self.log.trace("%i compartments found with name %s", len(compartments), name)

        return compartments

    def create_compartment(
            self,
            name: str,
            description: str,
            compartment_id: str = None,
            freeform_tags: dict[str, str] = None
    ) -> oci.identity.models.compartment.Compartment:
        '''Create compartment

        Parameters
        ----------
        name : str
            name of the compartment to create
        description : str
            compartment description
        compartment_id : str
            create compartment under this compartment
            if None, use the root compartment
        freeform_tags : dict[str, str]
            add tags

        Returns
        -------
        oci.identity.models.compartment.Compartment
            {"compartment_id": "ocid1.tenancy.oc1..",
             "defined_tags": {
               "Oracle-Tags": {
                 "CreatedBy": "default/",
                 "CreatedOn": "2023-03-23"
               }
             },
             "description": "Compartment to store Terraform created resources",
             "freeform_tags": {},
             "id": "ocid1.compartment.oc1..",
             "inactive_status": null,
             "is_accessible": null,
             "lifecycle_state": "ACTIVE",
             "name": "compartment-terraform",
             "time_created": "2023-03-23"}
        '''

        if compartment_id is None:
            compartment_id = self.config['tenancy']

        create_compartment_details = oci.identity.models.CreateCompartmentDetails(
                                                            compartment_id=compartment_id,
                                                            name=name,
                                                            description=description,
                                                            freeform_tags=freeform_tags)

        try:
            compartment = self.identity_client.create_compartment(
                            create_compartment_details=create_compartment_details).data
        except oci.exceptions.ServiceError as err:
            if 'already exists' in str(err.message):
                self.log.warning("Compartment %s already exists.", name)
                compartment = self.identity_client.list_compartments(compartment_id=compartment_id,
                                                                     name=name).data[0]
            else:
                raise
        else:
            self.log.success("Compartment %s created.", compartment.name)
            return compartment

        update_compartment_details = {}

        # check description
        if compartment.description != description:
            update_compartment_details['description'] = description

        # update freeform tags
        if bool(freeform_tags) is True:
            update_tags = self.set_freeform_tags(existing_tags=compartment.freeform_tags,
                                                 set_tags=freeform_tags)
            if bool(update_tags) is True:
                update_compartment_details['freeform_tags'] = update_tags

        if bool(update_compartment_details) is True:
            self.log.debug("Updating compartment %s with %s",
                            compartment.name, str(update_compartment_details))
            update_compartment_details = oci.identity.models.UpdateGroupDetails(
                                                                **update_compartment_details)
            compartment = self.identity_client.update_compartment(
                                        compartment_id=compartment.id,
                                        update_compartment_details=update_compartment_details).data

        return compartment

    def create_policy(self,
                      name: str,
                      description: str,
                      statements: list[str],
                      compartment_id: str = None,
                      freeform_tags: dict[str, str] = None
    ) -> oci.identity.models.policy.Policy:
        '''Create policies
        
        Parmeters
        ---------
        name : str, required
            name of the policy to create
        description : str, required
            policy description
        statements : list[str], required
            policy statements
        freeform_tags : dict[str, str]
            tags

        Returns
        -------
        oci.identity.models.policy.Policy
            {"compartment_id": "ocid1.tenancy.oc1..",
             "description": "group-terraform managed policies",
             "freeform_tags": {},
             "id": "ocid1.policy.oc1..",
             "inactive_status": null,
             "lifecycle_state": "ACTIVE",
             "name": "group-terraform-policies",
             "statements": [
                "Allow group group-terraform to manage all-resources in compartment cpm-terraform",
             ],
             "time_created": "2023-04-12",
             "version_date": null}
        '''
        # use root compartment if not provided
        if compartment_id is None:
            compartment_id = self.config['tenancy']

        # create policy
        create_policy_details = oci.identity.models.CreatePolicyDetails(
                                                        compartment_id=compartment_id,
                                                        name=name,
                                                        description=description,
                                                        statements=statements,
                                                        freeform_tags=freeform_tags)
        try:
            policy = self.identity_client.create_policy(
                            create_policy_details=create_policy_details).data
        except oci.exceptions.ServiceError as err:
            if err.code == 'PolicyAlreadyExists':
                self.log.warning("Policy name %s already exists", name)
                policy = self.identity_client.list_policies(compartment_id=compartment_id,
                                                            name=name).data[0]
            else:
                raise
        else:
            self.log.success("Policy %s created with the statemants %s",
                             policy.name, policy.statements)
            return policy

        # check if policy needs updating
        update_policy_details = {}

        # check description
        if policy.description != description:
            update_policy_details['description'] = description

        if bool(freeform_tags) is True:
            update_tags = self.set_freeform_tags(existing_tags=policy.freeform_tags,
                                                 set_tags=freeform_tags)
            if bool(update_tags) is True:
                update_policy_details['freeform_tags'] = update_tags

        # validate if all the statements are in policy
        policy_statements = copy.deepcopy(policy.statements)

        for statement in statements:
            if statement not in policy_statements:
                policy_statements.append(statement)

        if len(policy_statements) != len(policy.statements):
            update_policy_details['statements'] = policy_statements
        else:
            self.log.trace("Policy %s contains all the provided statements", policy.name)

        # update policy
        if bool(update_policy_details) is True:
            self.log.debug("Updating policy %s with %s", policy.name, str(update_policy_details))
            update_policy_details = oci.identity.models.UpdatePolicyDetails(
                                                            **update_policy_details)
            policy = self.identity_client.update_policy(
                                                policy_id=policy.id,
                                                update_policy_details=update_policy_details).data
            self.log.success("Policy %s updated.", policy.name)

        return policy

    def get_vaults(self,
                   compartment: oci.identity.models.compartment.Compartment,
                   name: str = None
    ) -> list[oci.key_management.models.vault_summary.VaultSummary]:
        '''Get Vault'''
        vaults = self.kms_vault_client.list_vaults(compartment_id=compartment.id).data
        self.log.trace("%i vaults found in compartment %s", len(vaults), compartment.name)
        vaults = [v for v in vaults if v.lifecycle_state in ['ACTIVE', 'CREATING']]
        self.log.trace("%i vaults found that are active", len(vaults))

        if name is None:
            return vaults

        vaults = [v for v in vaults if v.display_name]
        self.log.trace("%i found with name %s", len(vaults), name)

        return vaults

    def create_vault(self,
                     name: str,
                     compartment: str,
                     freeform_tags: dict[str, str] = None
    ) -> oci.key_management.models.vault_summary.VaultSummary:
        ''''Create Vault

        Parameters
        ----------
        name : str, required
            name of vault to create
        compartment : oci.identity.models.compartment.Compartment, required
            create vault in this compartment
        freeform_tags : dict[str, str]
            add tags
        
        Returns
        -------
        oci.key_management.models.vault_summary.VaultSummary
            {"compartment_id": "ocid1.compartment.oc1..",
             "crypto_endpoint": "https://...-crypto.kms.ca-toronto-1.oraclecloud.com",
             "display_name": "vault-automation",
             "freeform_tags": {},
             "id": "ocid1.vault.oc1.",
             "lifecycle_state": "ACTIVE",
             "management_endpoint": "https://...-management.kms.ca-toronto-1.oraclecloud.com",
             "time_created": "2023-04-21",
             "vault_type": "DEFAULT"}
        '''

        try:
            vault = self.get_vaults(compartment=compartment, name=name)[0]
        except IndexError:
            self.log.debug("Creating Vault...")
            create_vault_details = oci.key_management.models.CreateVaultDetails(
                                                                compartment_id=compartment.id,
                                                                display_name=name,
                                                                vault_type='DEFAULT')
            vault = self.kms_vault_client.create_vault(
                                            create_vault_details=create_vault_details).data
            self.log.success("Successfully created vault %s in %s compartment",
                                vault, compartment.name)
            return vault
        self.log.info("Vault %s already exists in %s compartment",
                          vault.display_name, compartment.name)

        # updating Vault
        update_vault_details = {}

        if bool(freeform_tags) is True:
            update_tags = self.set_freeform_tags(existing_tags=vault.freeform_tags,
                                                 set_tags=freeform_tags)
            if bool(update_tags) is True:
                update_vault_details['freeform_tags'] = update_tags

        if bool(update_vault_details) is True:
            self.log.debug("Updating vault %s with %s",
                          vault.display_name, str(update_vault_details))
            update_vault_details = oci.key_management.models.UpdateVaultDetails(
                                                                **update_vault_details)
            vault = self.kms_vault_client.update_vault(
                                            vault_id=vault.id,
                                            update_vault_details=update_vault_details).data
            self.log.success("Updated vault %s", vault.display_name)

        return vault

    def list_vault_keys(self,
                        compartment: oci.identity.models.compartment.Compartment,
                        vault: oci.key_management.models.vault_summary.VaultSummary,
                        algorithm: str = None,
                        name: str = None
    ) -> list[oci.key_management.models.key_summary.KeySummary]:
        '''List all the available keys in the vault

        Parameters
        ----------
        compartment : oci.identity.models.compartment.Compartment, required
            compartment to look in
        vault : oci.key_management.models.vault_summary.VaultSummary, required
            vault to look in
        name : str
            key display_name to search, default = None
        algorithm : str
            type of keys to look for, default = None
            e.g. AES

        Returns
        -------
        list[oci.key_management.models.vault_summary.VaultSummary]

        Raises
        ------
        oci.exceptions.ServiceError
            no permission to list keys
        '''
        kms_management_client = oci.key_management.kms_management_client.KmsManagementClient(
                                                **self.auth,
                                                service_endpoint=vault.management_endpoint)

        # get all keys in vault
        kms_keys = kms_management_client.list_keys(compartment_id=compartment.id).data
        self.log.trace("%i keys found in %s vault under %s compartment",
                       len(kms_keys), vault.display_name, compartment.name)
        kms_keys = [k for k in kms_keys if k.lifecycle_state in ['CREATING', 'ENABLED']]
        self.log.trace("%i keys are active", len(kms_keys))

        if algorithm is not None:
            kms_keys = [k for k in kms_keys if k.algorithm == algorithm]
            self.log.trace("%i keys found that are %s type.", len(kms_keys), algorithm)

        if name is None:
            return kms_keys

        kms_keys = [k for k in kms_keys if k.display_name == name]
        self.log.trace("%i keys filtered with name %s", len(kms_keys), name)

        return kms_keys

    def create_vault_key(self,
                         name: str,
                         vault: oci.key_management.models.vault_summary.VaultSummary,
                         compartment: oci.identity.models.compartment.Compartment,
                         algorithm: str = 'AES',
                         freeform_tags: dict[str, str] = None
    ) -> oci.key_management.models.key_summary.KeySummary:
        '''Create an AES key for encryption

        Parameters
        ----------
        name: str
            name of the key
        vault: oci.key_management.models.vault_summary.VaultSummary, required
            vault object
        compartment_id: oci.identity.models.compartment.Compartment, required
            compartmant OCID
        algorithm : str
            type of key to create, default = AES
        freeform_tags : dict[str, str]
            tags to add

        Returns
        -------
        oci.key_management.models.key_summary.KeySummary
        { "algorithm": "AES",
          "compartment_id": "ocid1.compartment.oc1..",
          "defined_tags": {},
          "display_name": "key-automation",
          "freeform_tags": {},
          "id": "ocid1.key.oc1.ca-toronto-1.",
          "lifecycle_state": "ENABLED",
          "protection_mode": "HSM",
          "time_created": "2022-03-12",
          "vault_id": "ocid1.vault.oc1.ca-toronto-1"}

        Raises
        ------
        oci.exceptions.ServiceError
            no permission to list keys
        '''
        # create key client
        kms_management_client = oci.key_management.kms_management_client.KmsManagementClient(
                                                        **self.auth,
                                                        service_endpoint=vault.management_endpoint)

        try:
            kms_key = self.list_vault_keys(compartment=compartment,
                                           vault=vault,
                                           algorithm=algorithm,
                                           name=name)[0]
        except IndexError:
            self.log.debug("%s key not found. Will create.", name)

            key_shape = oci.key_management.models.KeyShape(algorithm=algorithm, length=32)
            create_key_details = oci.key_management.models.CreateKeyDetails(
                                                                    compartment_id=compartment.id,
                                                                    display_name=name,
                                                                    key_shape=key_shape,
                                                                    protection_mode='HSM',
                                                                    freeform_tags=freeform_tags)

            kms_key = kms_management_client.create_key(create_key_details=create_key_details).data
            self.log.success("Successfuly created a encryption key: %s", kms_key)
            return kms_key
        self.log.info("%s %s key already exists.", kms_key.display_name, kms_key.algorithm)

        # updating key
        update_key_details = {}

        if bool(freeform_tags) is True:
            update_tags = self.set_freeform_tags(existing_tags=vault.freeform_tags,
                                                 set_tags=freeform_tags)
            if bool(update_tags) is True:
                update_key_details['freeform_tags'] = update_tags

        if bool(update_key_details) is True:
            self.log.debug("Updating vault key %s with %s",
                          kms_key.display_name, str(update_key_details))
            update_key_details = oci.key_management.models.UpdateVaultDetails(**update_key_details)
            kms_key = kms_management_client.update_key(key_id=kms_key.id,
                                                       update_key_details=update_key_details).data
            self.log.success("Updated vault key %s", kms_key.display_name)

        return kms_key

    def vault_list_secrets(self,
                           compartment: oci.identity.models.compartment.Compartment,
                           vault: oci.key_management.models.vault_summary.VaultSummary,
                           name: str = None
    ) -> list[oci.vault.models.secret_summary.SecretSummary]:
        '''List all the secrets in Vault

        Parameters
        ----------
        compartment : oci.identity.models.compartment.Compartment, required
            compartment the vault is located in
        vault : oci.key_management.models.vault_summary.VaultSummary, required
            vault the secret is in
        name : str
            name of the secret to look for

        Returns
        -------
        list[oci.vault.models.secret_summary.SecretSummary]
            [{
                "compartment_id": "ocid1.compartment.oc1..<REDACTED>",
                "description": null,
                "freeform_tags": {},
                "id": "ocid1.vaultsecret.oc1.ca-toronto-1.<REDACTED",
                "key_id": "ocid1.key.oc1.ca-toronto-1.<REDACTED>",
                "lifecycle_details": null,
                "lifecycle_state": "PENDING_DELETION",
                "secret_name": "testpassword1234",
                "time_created": "2023-06-28T01:55:30.571000+00:00",
                "time_of_current_version_expiry": null,
                "time_of_deletion": "2023-07-07T03:33:40.534000+00:00",
                "vault_id": "ocid1.vault.oc1.ca-toronto-1.<REDACTED>"
            }]
        '''
        search = { 'compartment_id': compartment.id,
                   'vault_id': vault.id}
        if name is not None:
            search['name'] = name

        secrets = self.vault_client.list_secrets(**search).data
        self.log.trace("%i secrets found in vault %s under compartment %s",
                       len(secrets), vault.display_name, compartment.name)
        if name is not None:
            self.log.trace("With secret name %s", name)

        return secrets

    def vault_get_secret(self,
                         secret: oci.vault.models.secret_summary.SecretSummary,
                         decode: bool = True) -> str:
        '''Get Secret Content

        Parameters
        ----------
        secret : oci.vault.models.secret_summary.SecretSummary, required
            the secret
        decode : bool
            decode the base64 string, default = False

        Returns
        -------
        str
        '''
        secret_bundle_content = self.secrets_client.get_secret_bundle(secret_id=secret.id).data
        secret_bundle_content = secret_bundle_content.secret_bundle_content

        if secret_bundle_content.content_type != 'BASE64':
            raise NotImplementedError(
                f"Secret in encoded in {secret_bundle_content.content_type}")

        if decode is True:
            try:
                return base64.b64decode(secret_bundle_content.content).decode()
            except UnicodeDecodeError as err:
                raise pyhomelab.oci.exceptions.OCISecretDecryptionFailed(
                    f"Unable to decode base64 secret {secret.secret_name}") from err

        return secret_bundle_content.content

    def vault_delete_secret_version(self,
                                    secret: oci.vault.models.secret_summary.SecretSummary
    ) -> None:
        '''Delete Deprecated secret versions

        Parameters
        ----------
        secret : oci.vault.models.secret_summary.SecretSummary, required
            secrets

        Returns
        -------
        None
        '''
        secret_versions = self.vault_client.list_secret_versions(secret_id=secret.id).data

        for secret_version in secret_versions:
            if 'DEPRECATED' in secret_version.stages and secret_version.time_of_deletion is None:
                self.log.trace("Secret %s version %i is deprecated. Will schedule deletion",
                               secret.secret_name, secret_version.version_number)
                time_of_deletion = dt.datetime.now() + dt.timedelta(hours=30)
                delete_details = oci.vault.models.ScheduleSecretVersionDeletionDetails(
                                time_of_deletion=time_of_deletion.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))

                counter = 0
                while True:
                    try:
                        _ = self.vault_client.schedule_secret_version_deletion(
                                secret_id=secret.id,
                                secret_version_number=secret_version.version_number,
                                schedule_secret_version_deletion_details=delete_details)
                    except oci.exceptions.TransientServiceError as err:
                        if counter == 10:
                            raise pyhomelab.oci.exceptions.OCISecretVersionDeletionFailed(
                                                                                    err) from err
                        if 'has a conflicting state of UPDATING' in str(err):
                            self.log.trace("Secret %s is in Updating state. Sleeping for 3 sec",
                                           secret.secret_name)
                            counter = counter + 1
                            time.sleep(3)
                            continue
                        self.log.success("Secret %s version %i will be deleted on %s",
                                         secret.secret_name,
                                         secret_version.version_number,
                                         str(time_of_deletion))
                        break

    def vault_set_secret(self,
                         compartment: oci.identity.models.compartment.Compartment,
                         vault: oci.key_management.models.vault_summary.VaultSummary,
                         key: oci.key_management.models.key_summary.KeySummary,
                         secret_name: str,
                         secret_content: str,
                         description: str = None):
        '''Set Vault Secret

        Parameters
        ----------
        compartment : oci.identity.models.compartment.Compartment, required
            compartment where vault is located
        vault : oci.key_management.models.vault_summary.VaultSummary, required
            vault to store the secret
        key : oci.key_management.models.key_summary.KeySummary, required
            key to encrypt secret with
        secret_name : str, required
            name of the secret
        secret_content : str, required
            string or base64
        description : str
            secret description default = None

        Returns
        -------
        oci.vault.models.secret_summary.SecretSummary
        '''
        # encode the secret content if not encoded
        if Helper.is_base64_encoded(value=secret_content) is False:
            self.log.trace('Provided secret content is not base64 encoded. Will encode.')
            secret_content = base64.b64encode(bytes(secret_content, encoding='utf8')).decode()

        # set secret content details
        secret_content_details = oci.vault.models.Base64SecretContentDetails(
            content_type=oci.vault.models.SecretContentDetails.CONTENT_TYPE_BASE64,
            name=dt.datetime.now().strftime('%Y%m%d%H%M%S'),
            stage='CURRENT',
            content=secret_content)

        try:
            secret = self.vault_list_secrets(compartment=compartment,
                                             vault=vault,
                                             name=secret_name)[0]
        except IndexError:
            self.log.trace("Secret %s does not exist. Will create.", secret_name)

            create_secret_details = oci.vault.models.CreateSecretDetails(
                compartment_id=compartment.id,
                secret_content=secret_content_details,
                secret_name=secret_name,
                vault_id=vault.id,
                description=description,
                key_id=key.id)

            secret = self.vault_client.create_secret(
                                                create_secret_details=create_secret_details).data
            self.log.success("Secret %s created", secret.secret_name)
            return secret

        self.log.trace("Secret %s exists.", secret.secret_name)

        if secret.lifecycle_state not in ['ACTIVE', 'CREATING']:
            raise pyhomelab.oci.exceptions.OCISecretUpdateFailed(
                f"Secret {secret.secret_name} is in {secret.lifecycle_state} state. "
                'Unable to update')

        # checking current content
        if self.vault_get_secret(secret=secret, decode=False) == secret_content:
            self.log.info("Secret %s already set to the provided secret content",
                          secret.secret_name)
            return secret
        self.log.debug("Secret %s needs updating", secret.secret_name)

        # update the secret
        update_secret_details = oci.vault.models.UpdateSecretDetails(
                                                            secret_content=secret_content_details)
        secret = self.vault_client.update_secret(secret_id=secret.id,
                                                 update_secret_details=update_secret_details).data
        self.log.success("Secret %s content updated.", secret.secret_name)

        # cleaning up old versions
        self.vault_delete_secret_version(secret=secret)

        return secret

    def vault_delete_secret(self,
                            name: str,
                            compartment: oci.identity.models.compartment.Compartment,
                            vault: oci.key_management.models.vault_summary.VaultSummary
    ) -> None:
        '''Delete a Vault Secret

        Parameters
        ----------
        name : str, required
            Name of the secret
        compartment : oci.identity.models.compartment.Compartment, required
            compartment of vault
        vault : oci.key_management.models.vault_summary.VaultSummary
            vault of secret location

        Raises
        ------
        pyhomelab.oci.exceptions.OCISecretDeletionFailed
            Secret not in active state
        '''

        try:
            secret = self.vault_list_secrets(compartment=compartment, vault=vault, name=name)[0]
        except IndexError as err:
            raise pyhomelab.oci.exceptions.OCISecretDoesNotExist(
                f"Secret {name} does not exist in Vault {vault.display_name} under "
                f"{compartment.name} compartment") from err

        if secret.lifecycle_state not in ['CREATING', 'ACTIVE']:
            raise pyhomelab.oci.exceptions.OCISecretDeletionFailed(
                f"Secret {secret.secret_name} is in {secret.lifecycle_state} state.")

        time_of_deletion = dt.datetime.now() + dt.timedelta(hours=30)
        self.log.debug("Scheduling secret %s to be deleted on %s",
                       secret.secret_name, time_of_deletion)
        delete_details = oci.vault.models.ScheduleSecretDeletionDetails(
                            time_of_deletion=time_of_deletion.strftime('%Y-%m-%dT%H:%M:%S.%fZ'))

        _ = self.vault_client.schedule_secret_deletion(
                                                secret_id=secret.id,
                                                schedule_secret_deletion_details=delete_details)
        self.log.success("Secret %s deleted.", secret.secret_name)
