"""This modules provides the class ``AltimeterConfig`` that allows to generate
a dictionary that can be used to configure an Altimeter scan."""

import os
import copy
from urllib import parse

from graph_altimeter import EnvVarNotSetError
from graph_altimeter.scan import parse_role_arn


class AltimeterConfig:
    """Stores the basic dictionary configuration for Altimeter and provides
    methods for constructing that dictionary form env vars. It also allows to
    generate a concrete Altimeter scan configuration based on the stored basic
    configuration."""

    def __init__(self, config_dict):
        self.__config_dict = config_dict

    @classmethod
    def from_env(cls):
        """Creates an ``AltimeterConfig`` instance by reading the required env
        vars."""
        max_account_scan_threads = os.getenv("MAX_ACCOUNT_SCAN_THREADS", "1")
        max_svc_scan_threads = os.getenv("MAX_SVC_SCAN_THREADS", "1")

        gremlin_endpoint = os.getenv("GREMLIN_ENDPOINT", "")
        if gremlin_endpoint == "":
            raise EnvVarNotSetError("GREMLIN_ENDPOINT")

        neptune_auth_mode = os.getenv("NEPTUNE_AUTH_MODE", "")
        neptune_region = None
        if neptune_auth_mode != "":
            neptune_region = os.getenv("NEPTUNE_REGION", "eu-west-1")

        artifact_path = os.getenv("ARTFACT_PATH", "/tmp/altimeter_account")

        target_account_role = os.getenv("TARGET_ACCOUNT_ROLE", "")
        if target_account_role == "":
            raise EnvVarNotSetError("TARGET_ACCOUNT_ROLE")

        neptune_endpoint_parts = parse.urlparse(gremlin_endpoint)
        ssl = ((neptune_endpoint_parts.scheme == "wss") or
               (neptune_endpoint_parts.scheme == "https"))

        # TODO: We decided to use the european regions to scan global services
        # (defined at preferred_account_scan_regions). This list is hardcoded,
        # which means that new global services not supported by those regions
        # would not be scanned.
        config_dict = {
            'artifact_path': artifact_path,
            'graph_name': "alti",
            'concurrency': {
                'max_account_scan_threads': max_account_scan_threads,
                'max_svc_scan_threads': max_svc_scan_threads,
            },
            'scan': {
                'scan_sub_accounts': False,
                'regions': [],
                'accounts': [],
                'preferred_account_scan_regions': [
                    "eu-central-1",
                    "eu-north-1",
                    "eu-west-1",
                    "eu-west-2",
                    "eu-west-3",
                ]
            },
        }
        neptune_config_dict = {
            'use_lpg': "true",
            'host': neptune_endpoint_parts.hostname,
            'port': neptune_endpoint_parts.port,
            'region': neptune_region,
            'ssl': ssl,
            'auth_mode': neptune_auth_mode,
        }

        if neptune_auth_mode != "":
            neptune_config_dict['auth_mode'] = neptune_auth_mode
        else:
            neptune_config_dict['auth_mode'] = "default"

        config_dict['neptune'] = neptune_config_dict

        # We don't prune any graph but the AWSConfig class requires this
        # parameter to be defined.
        config_dict['pruner_max_age_min'] = 0

        return AltimeterConfig(config_dict)

    def config_dict(
        self,
        target_account_id,
        target_account_role,
        trampoline_account_role_arn=None,
    ):
        """This function returns a dictionary suitable to run an Altimeter Scan by
        using the base dictionary stored in the instance, a ``target_account_id``
        to scan, the ``target_account_role`` to be assumed in
        that account and an optional trampoline account."""
        config_dict = copy.deepcopy(self.__config_dict)
        config_dict["accessor"] = account_accessor_dict(
            target_account_role,
            trampoline_account_role_arn,
        )
        config_dict['scan']['accounts'] = [target_account_id]
        return config_dict


def account_accessor_dict(target_account_role, trampoline_account_role_arn):
    """Given a role name in the target account and a trampoline role, this
    function generates the Altimeter config dict needed to scan the target
    account using the trampoline role."""
    access_steps = [{'role_name': target_account_role}]

    if trampoline_account_role_arn is not None:
        trampoline_account_id, trampoline_role_name = parse_role_arn(
            trampoline_account_role_arn,
        )
        access_steps = [
            {
                "account_id": trampoline_account_id,
                "role_name": trampoline_role_name,
            },
            {
                "role_name": target_account_role,
            },
        ]

    multihop_accessor = {
        'cache_creds': True,
        'multi_hop_accessors': [
            {
                'role_session_name': "audit_session",
                'access_steps': access_steps,
            }
        ]
    }

    return multihop_accessor
