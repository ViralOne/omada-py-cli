"""`vpn-client` subcommand — OpenAPI v1 Client-to-Site VPN (backend: omada.openapi).

Wired into the unified CLI (omada.cli). Uses its own OAuth2 auth + logging,
independent of the internal API v2 controller.
"""
import argparse
import logging

from .openapi import OmadaConfig, OmadaVPNManager, VPNAction


def add_vpn_client_subparser(subparsers) -> None:
    """Register the `vpn-client` subcommand on the unified parser."""
    p = subparsers.add_parser(
        'vpn-client',
        help='Manage Client-to-Site VPN clients via the official OpenAPI v1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --vpn MyVPN --action enable            # Enable a single VPN
  %(prog)s --vpn MyVPN1 MyVPN2 --action disable   # Disable multiple VPNs
  %(prog)s --vpn MyVPN --action restart           # Restart a VPN
  %(prog)s --action token_only                    # Generate token only
  %(prog)s                                         # Use environment variables

Environment Variables:
  OMADA_URL, OMADA_CLIENT_ID, OMADA_CLIENT_SECRET, OMADA_OMADAC_ID,
  OMADA_USERNAME, OMADA_PASSWORD, OMADA_VPN_NAME, OMADA_VPN_ACTION
        """,
    )
    p.add_argument('--vpn', '-v', nargs='+',
                   help='VPN client name(s) to manage. Can specify multiple names.')
    p.add_argument('--action', '-a',
                   choices=['enable', 'disable', 'restart', 'token_only'],
                   help='Action to perform on the VPN client(s)')


def run_vpn_client(args) -> int:
    """Execute the OpenAPI v1 VPN client action from parsed args."""
    if args.vpn and not args.action:
        logging.error("--action/-a is required when --vpn/-v is specified")
        return 1

    try:
        config = OmadaConfig.from_env_and_args(args)
        manager = OmadaVPNManager(config)

        manager.logger.info(f"Connecting to Omada Controller at {config.base_url}")
        if len(config.vpn_names) == 1:
            manager.logger.info(f"Target VPN: {config.vpn_names[0]} (Action: {config.vpn_action.value})")
        else:
            manager.logger.info(f"Target VPNs: {', '.join(config.vpn_names)} (Action: {config.vpn_action.value})")

        manager.authenticate()

        # Handle token-only mode
        if config.vpn_action == VPNAction.TOKEN_ONLY:
            manager.logger.info("✅ Token generated successfully and saved to omada_token.json")
            manager.logger.info("Exiting as requested (token_only mode)")
            return 0

        # Single VPN
        if len(config.vpn_names) == 1:
            success = manager.execute_vpn_action(config.vpn_names[0], config.vpn_action)
            if success:
                manager.logger.info(f"✅ Successfully {config.vpn_action.value}d VPN client '{config.vpn_names[0]}'")
                return 0
            manager.logger.error(f"❌ Failed to {config.vpn_action.value} VPN client '{config.vpn_names[0]}'")
            return 1

        # Multiple VPNs
        manager.logger.info(f"\n🚀 Starting batch operation for {len(config.vpn_names)} VPN clients...")
        results = manager.execute_vpn_actions_for_multiple(config.vpn_names, config.vpn_action)
        successful = [name for name, ok in results.items() if ok]
        failed = [name for name, ok in results.items() if not ok]

        manager.logger.info(f"\n📊 Batch operation summary:")
        manager.logger.info(f"✅ Successful: {len(successful)}/{len(config.vpn_names)}")
        if successful:
            manager.logger.info(f"   - {', '.join(successful)}")
        if failed:
            manager.logger.info(f"❌ Failed: {len(failed)}/{len(config.vpn_names)}")
            manager.logger.info(f"   - {', '.join(failed)}")
        return 0 if len(failed) == 0 else 1

    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        return 1
