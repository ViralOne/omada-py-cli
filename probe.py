#!/usr/bin/env python3
"""Read-only prober for investigating the Omada internal API v2.

Reuses the authenticated OmadaController from omada_api_v2 and issues plain
GET requests to arbitrary endpoints so we can discover the real shapes/paths
for networking config (VLANs, WLAN/SSID, ACL) before writing CLI commands.

Usage:
    python probe.py sites
    python probe.py "sites/{sid}/setting/lan/networks"
    python probe.py "sites/{sid}/setting/wlans" "sites/{sid}/setting/firewall/acls"

Notes:
    - {sid} is replaced with the current site id.
    - This only performs GET. It never creates/modifies/deletes anything.
"""
import os
import sys
import json

from dotenv import load_dotenv
from omada.controller import create_controller
from omada.cli import setup_logging

load_dotenv()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    setup_logging(debug=False)
    controller = create_controller(
        os.getenv("OMADA_URL"),
        os.getenv("OMADA_USERNAME"),
        os.getenv("OMADA_PASSWORD"),
    )

    controller.get_sites()
    sid = controller.current_site_key
    print(f"# omadacId={controller.controller_id}  current_site={sid}\n")

    # Most internal v2 "grid" endpoints require pagination params.
    params = {"currentPage": 1, "currentPageSize": 100}

    # Any CLI arg shaped like key=value becomes an extra query param.
    endpoints = []
    for arg in sys.argv[1:]:
        if "=" in arg and not arg.startswith("sites"):
            key, val = arg.split("=", 1)
            params[key] = val
        else:
            endpoints.append(arg)

    for raw_ep in endpoints:
        endpoint = raw_ep.replace("{sid}", sid or "")
        result = controller._request(endpoint, method="GET", params=dict(params))
        print(f"===== GET /{controller.controller_id}/api/v2/{endpoint} =====")
        if result is None:
            print("  <no result / error - see log above>\n")
            continue
        payload = result.get("result", result)
        text = json.dumps(payload, indent=2, ensure_ascii=False)
        # Truncate huge payloads so the terminal stays readable
        if len(text) > 6000:
            text = text[:6000] + f"\n... [truncated, {len(text)} chars total]"
        print(text + "\n")


if __name__ == "__main__":
    main()
