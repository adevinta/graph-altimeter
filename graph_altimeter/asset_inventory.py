""""This module implements functions to interact with the Asset Inventory."""

import urllib
import urllib.parse
import json


def get_aws_accounts(asset_inventory_api_url):
    """Gets the non-expired AWS accounts stored in the Asset Inventory given
    its base url."""
    assets_url = f"{asset_inventory_api_url}/assets?" \
                 f"asset_type=AWSAccount"
    request = urllib.request.Request(url=assets_url, method="GET")

    accounts_info = []
    with urllib.request.urlopen(request) as response:
        accounts_info = json.load(response)

    return [account['identifier'] for account in accounts_info]
