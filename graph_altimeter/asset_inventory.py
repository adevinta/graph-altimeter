""""This module implements functions to interact with the Asset Inventory."""

import urllib
import urllib.parse
import json
from datetime import (
    datetime,
    timezone,
)


def get_aws_accounts(asset_inventory_api_url):
    """Gets the non-expired AWS accounts stored in the Asset Inventory given
    its base url."""
    valid_at = datetime.now(timezone.utc).isoformat()
    valid_at_q = urllib.parse.quote_plus(valid_at)
    assets_url = f"{asset_inventory_api_url}/assets?" \
                 f"asset_type=AWSAccount&valid_at={valid_at_q}"
    request = urllib.request.Request(url=assets_url, method="GET")

    accounts_info = []
    with urllib.request.urlopen(request) as response:
        accounts_info = json.load(response)

    return [account['identifier'] for account in accounts_info]
