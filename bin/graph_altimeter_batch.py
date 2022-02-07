"""graph_altimeter_batch is a tool used to populate the Altimeter Universe in
the Security Graph. It is typically launched as a batch job."""

import os
import sys
import logging

from altimeter.core.config import AWSConfig

from graph_altimeter import (
    EnvVarNotSetError,
    AltimeterError
)
from graph_altimeter.scan import run
from graph_altimeter.scan.config import AltimeterConfig
from graph_altimeter.asset_inventory import get_aws_accounts


logger = logging.getLogger('graph_altimeter_batch')


def main():
    """Entrypoint of the graph_altimeter_batch command."""
    debug = os.getenv('DEBUG', '') != ''
    config_root_logger(debug)

    try:
        run_scan()
    except AltimeterError as e:
        logger.error('error running altimeter scan: %s', e)
        sys.exit(1)


def run_scan():
    """Scans the accounts defined in the Asset Inventory using Altimeter."""
    asset_inventory_api_url = os.getenv('ASSET_INVENTORY_API_URL', None)
    if asset_inventory_api_url is None:
        raise EnvVarNotSetError('ASSET_INVENTORY_API_URL')

    target_account_role = os.getenv('TARGET_ACCOUNT_ROLE', None)
    if target_account_role is None:
        raise EnvVarNotSetError('TARGET_ACCOUNT_ROLE')

    trampoline_account_role_arn = os.getenv('TRAMPOLINE_ROLE_ARN', None)

    accounts_per_batch = os.getenv("ACCOUNTS_BATCH", None)
    if accounts_per_batch is None:
        accounts_per_batch = 1
    accounts = get_aws_accounts(asset_inventory_api_url)
    batches = len(accounts) // accounts_per_batch
    if len(accounts) % accounts_per_batch > 0:
        batches = batches + 1

    for i in range(0, batches):
        from_acc = i * accounts_per_batch
        to_acc = from_acc + accounts_per_batch
        if to_acc >= len(accounts):
            to_acc = from_acc + (accounts % accounts_per_batch)
        batch = accounts[from_acc::to_acc]
        logger.info(
            "scanning accounts %i to %i of %i",
            from_acc, to_acc, len(accounts)
        )
        config = AltimeterConfig.from_env()
        scan_config = config.config_dict(
            batch,
            target_account_role,
            trampoline_account_role_arn,
        )
        altimeter_config = AWSConfig.parse_obj(scan_config)
        run(altimeter_config)


def config_root_logger(debug):
    """Configures the root logger. It sets the logging level to ``DEBUG`` if
    the param ``debug`` is true. Otherwise, the logging level is set to
    ``INFO``."""
    root_logger = logging.getLogger()
    log_level = logging.DEBUG if debug else logging.INFO
    root_logger.setLevel(log_level)

    logging_handler = logging.StreamHandler(stream=sys.stderr)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logging_handler.setFormatter(formatter)

    root_logger.addHandler(logging_handler)


if __name__ == '__main__':
    main()
