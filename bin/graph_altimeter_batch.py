"""graph_altimeter_batch is a tool used to populate the Altimeter Universe in
the Security Graph. It is typically launched as a batch job."""

import os
import sys
import logging

from altimeter.core.config import AWSConfig

from graph_altimeter import EnvVarNotSetError
from graph_altimeter.scan import run
from graph_altimeter.scan.config import AltimeterConfig
from graph_altimeter.asset_inventory import get_aws_accounts


logger = logging.getLogger('graph_altimeter_batch')


def main():
    """Entrypoint of the graph_altimeter_batch command."""
    debug = os.getenv('DEBUG', '') != ''
    config_root_logger(debug)
    logger.info("started scanning accounts")
    run_scan()
    logger.info("finished scanning accounts")


def run_scan():
    # pylint: disable=broad-except
    """Scans the accounts defined in the Asset Inventory using Altimeter."""
    asset_inventory_api_url = os.getenv('ASSET_INVENTORY_API_URL', None)
    accounts_to_scan = os.getenv("ACCOUNTS", None)
    if asset_inventory_api_url is None and accounts_to_scan is None:
        raise EnvVarNotSetError('ASSET_INVENTORY_API_URL')

    target_account_role = os.getenv('TARGET_ACCOUNT_ROLE', None)
    if target_account_role is None:
        raise EnvVarNotSetError('TARGET_ACCOUNT_ROLE')

    trampoline_account_role_arn = os.getenv('TRAMPOLINE_ROLE_ARN', None)

    accounts = []
    if accounts_to_scan is not None:
        accounts = accounts_to_scan.split(",")
    else:
        accounts = get_aws_accounts(asset_inventory_api_url)

    for i, account_id in enumerate(accounts):
        logger.info(
            "scanning account %s (%s/%s)",
            account_id,
            i + 1,
            len(accounts)
        )
        config = AltimeterConfig.from_env()
        scan_config = config.config_dict(
            account_id,
            target_account_role,
            trampoline_account_role_arn,
        )
        altimeter_config = AWSConfig.parse_obj(scan_config)
        try:
            run(altimeter_config, account_id)
        except Exception as e:
            logger.error(
                "error scanning account %s, detail: %s",
                account_id,
                str(e)
            )


def config_root_logger(debug):
    """Configures the root logger. It sets the logging level to ``DEBUG`` if
    the param ``debug`` is true. Otherwise, the logging level is set to
    ``INFO``."""
    root_logger = logging.getLogger()

    if debug:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.INFO)
        # Altimeter's INFO level is too verbose. So we set it to ERROR on
        # non-debug mode.
        logging.getLogger('altimeter').setLevel(logging.ERROR)

    logging_handler = logging.StreamHandler(stream=sys.stderr)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logging_handler.setFormatter(formatter)

    root_logger.addHandler(logging_handler)


if __name__ == '__main__':
    main()
