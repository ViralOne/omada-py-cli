"""Command-line interface: logging setup, argument parsing and dispatch."""
import argparse
import os
import sys
import logging
from datetime import datetime

from .envtools import load_env, init_config, config_hint

from .controller import create_controller
from .commands import (
    cmd_sites, cmd_summary, cmd_devices, cmd_clients,
    cmd_networks, cmd_ssids, cmd_groups, cmd_acl,
    cmd_acl_create, cmd_acl_edit, cmd_group_set_mask, cmd_mdns, cmd_dhcp_reserve,
    cmd_vpn_tunnels, cmd_vpn_list, cmd_vpn_enable, cmd_vpn_disable,
    cmd_vpn_status, cmd_vpn_restart, cmd_alerts,
    cmd_find_device, cmd_find_client,
    cmd_wireguard_peers, cmd_wireguard_servers, cmd_wireguard_insights,
    cmd_wireguard_summary, cmd_wireguard_peer_create, cmd_wireguard_peer_delete,
    cmd_wireguard_peer_enable, cmd_wireguard_peer_disable,
    cmd_wireguard_peer_status, cmd_wireguard_peer_restart, cmd_wireguard_peer_list,
)
from .actions import CUSTOM_ACTIONS, cmd_custom_action
from .openapi_cli import add_vpn_client_subparser, run_vpn_client


def setup_logging(debug=False):
    """Setup logging configuration with timestamps"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging format with timestamp
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Set up root logger
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format=log_format,
        datefmt=date_format,
        handlers=[
            # File handler for all logs
            logging.FileHandler(f'logs/omada_api_{datetime.now().strftime("%Y%m%d")}.log'),
            # Console handler for INFO and above
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set console handler to only show INFO and above
    console_handler = logging.getLogger().handlers[-1]
    console_handler.setLevel(logging.INFO)
    
    # Create specific loggers
    api_logger = logging.getLogger('omada_api')
    vpn_logger = logging.getLogger('omada_vpn')
    
    return api_logger, vpn_logger


def get_config():
    """Get configuration from environment variables or defaults"""
    return {
        'url': os.getenv('OMADA_URL'),
        'username': os.getenv('OMADA_USERNAME'),
        'password': os.getenv('OMADA_PASSWORD')
    }


def create_parser():
    """Create the argument parser"""
    parser = argparse.ArgumentParser(
        description='Omada Controller CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sites                           # List all sites
  %(prog)s summary                         # Show network summary
  %(prog)s devices                         # List all devices
  %(prog)s clients --active-only           # List active clients only
  %(prog)s vpn list                        # List VPN configurations
  %(prog)s vpn enable MyVPN                # Enable a VPN
  %(prog)s vpn disable MyVPN               # Disable a VPN
  %(prog)s vpn restart MyVPN               # Restart a VPN (disable, wait, enable)
  %(prog)s vpn status MyVPN                # Check VPN status
  %(prog)s alerts --limit 10               # Show 10 recent alerts
  %(prog)s find device "Router"            # Find device by name (fuzzy search)
  %(prog)s find device --search-type mac "aa:bb:cc" # Find device by MAC
  %(prog)s find client "Galaxy"            # Find client by name (fuzzy search)
  %(prog)s find client --search-type ip "192.168"    # Find client by IP
  %(prog)s find client --all "Phone"       # Search all clients (not just active)
  %(prog)s actions vpn-health-check        # Check VPN health and restart if needed
  %(prog)s actions network-status          # Generate network status report
  %(prog)s actions vpn-bulk-restart --force # Restart all enabled VPNs
        """
    )
    
    parser.add_argument('--url', help='Omada Controller URL')
    parser.add_argument('--username', help='Username')
    parser.add_argument('--password', help='Password')
    parser.add_argument('--site', help='Site ID or name')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Config scaffolding
    subparsers.add_parser('init', help='Create ~/.config/omada/.env config template')

    # Sites command
    subparsers.add_parser('sites', help='List all sites')
    
    # Summary command
    summary_parser = subparsers.add_parser('summary', help='Show network summary')
    
    # Devices command
    devices_parser = subparsers.add_parser('devices', help='List devices')
    
    # Clients command
    clients_parser = subparsers.add_parser('clients', help='List clients')
    clients_parser.add_argument('--active-only', action='store_true', default=True, help='Show only active clients')
    clients_parser.add_argument('--all', action='store_true', help='Show all clients (active and inactive)')
    clients_parser.add_argument('--limit', type=int, default=50, help='Limit number of results')

    # Networking config commands
    subparsers.add_parser('networks', help='List wired networks (VLANs)')

    ssids_parser = subparsers.add_parser('ssids', help='List SSIDs')
    ssids_parser.add_argument('--wlan-id', help='WLAN group id (defaults to the primary group)')

    subparsers.add_parser('groups', help='List IP / domain groups')

    acl_parser = subparsers.add_parser('acl', help='ACL rules (list/create/edit)')
    acl_sub = acl_parser.add_subparsers(dest='acl_command')

    acl_list = acl_sub.add_parser('list', help='List ACL rules')
    acl_list.add_argument('--type', choices=['gateway', 'switch', 'eap'], default='gateway',
                          help='ACL type (default: gateway)')

    acl_create = acl_sub.add_parser('create', help='Create an ACL rule')
    acl_create.add_argument('name')
    acl_create.add_argument('--type', choices=['gateway', 'switch', 'eap'], default='gateway')
    acl_create.add_argument('--policy', choices=['permit', 'deny'], required=True)
    acl_create.add_argument('--src-type', choices=['network', 'ipgroup', 'ipport'], required=True)
    acl_create.add_argument('--src', nargs='+', required=True, help='source id(s)')
    acl_create.add_argument('--dst-type', choices=['network', 'ipgroup', 'ipport'], required=True)
    acl_create.add_argument('--dst', nargs='+', required=True, help='destination id(s)')
    acl_create.add_argument('--protocols', nargs='+', type=int, default=[256], help='default: 256 (all)')
    acl_create.add_argument('--disabled', action='store_true', help='create the rule disabled')
    acl_create.add_argument('--dry-run', action='store_true', help='print the request body, do not write')

    acl_edit = acl_sub.add_parser('edit', help='Edit an ACL rule')
    acl_edit.add_argument('--type', choices=['gateway', 'switch', 'eap'], default='gateway')
    acl_edit.add_argument('--id', help='rule id to edit')
    acl_edit.add_argument('--name', help='rule name to locate (if --id not given)')
    acl_edit.add_argument('--rename', help='new name')
    acl_edit.add_argument('--policy', choices=['permit', 'deny'])
    acl_edit.add_argument('--src-type', choices=['network', 'ipgroup', 'ipport'])
    acl_edit.add_argument('--src', nargs='+')
    acl_edit.add_argument('--dst-type', choices=['network', 'ipgroup', 'ipport'])
    acl_edit.add_argument('--dst', nargs='+')
    acl_edit.add_argument('--status', choices=['enable', 'disable'])
    acl_edit.add_argument('--dry-run', action='store_true', help='print the request body, do not write')

    # mDNS reflector (read-only; enable payload undocumented on v6.2)
    subparsers.add_parser('mdns', help='Show mDNS reflector state')

    # Group write ops
    group_parser = subparsers.add_parser('group', help='IP/domain group operations')
    group_sub = group_parser.add_subparsers(dest='group_command')
    gsm = group_sub.add_parser('set-mask', help="Set subnet mask on a group's IP entries")
    gsm.add_argument('name')
    gsm.add_argument('mask', type=int)
    gsm.add_argument('--dry-run', action='store_true', help='print the request body, do not write')

    # DHCP operations
    dhcp_parser = subparsers.add_parser('dhcp', help='DHCP operations')
    dhcp_sub = dhcp_parser.add_subparsers(dest='dhcp_command')
    dres = dhcp_sub.add_parser('reserve', help='Reserve a fixed IP for a client')
    dres.add_argument('client', help='client name or MAC')
    dres.add_argument('--ip', help='IP to reserve (default: the client current IP)')
    dres.add_argument('--net-id', help='network id (default: auto-detect from IP)')
    dres.add_argument('--dry-run', action='store_true', help='print the request body, do not write')

    # VPN commands
    vpn_parser = subparsers.add_parser('vpn', help='VPN management')
    vpn_subparsers = vpn_parser.add_subparsers(dest='vpn_command', help='VPN commands')
    
    vpn_subparsers.add_parser('list', help='List VPN configurations')
    vpn_subparsers.add_parser('tunnels', help='Show active VPN tunnels')
    
    vpn_enable_parser = vpn_subparsers.add_parser('enable', help='Enable a VPN')
    vpn_enable_parser.add_argument('name', help='VPN name')
    
    vpn_disable_parser = vpn_subparsers.add_parser('disable', help='Disable a VPN')
    vpn_disable_parser.add_argument('name', help='VPN name')
    
    vpn_status_parser = vpn_subparsers.add_parser('status', help='Check VPN status')
    vpn_status_parser.add_argument('name', help='VPN name')
    
    vpn_restart_parser = vpn_subparsers.add_parser('restart', help='Restart a VPN (disable, wait 2s, enable)')
    vpn_restart_parser.add_argument('name', help='VPN name')
    
    # WireGuard commands
    wg_parser = subparsers.add_parser('wireguard', help='WireGuard management')
    wg_subparsers = wg_parser.add_subparsers(dest='wg_command', help='WireGuard commands')
    
    wg_peers_parser = wg_subparsers.add_parser('peers', help='List WireGuard peers')
    wg_peers_parser.add_argument('--site', help='Site key (uses current site if not specified)')
    wg_peers_parser.add_argument('--page', type=int, default=1, help='Page number')
    wg_peers_parser.add_argument('--page-size', type=int, default=10, help='Items per page')
    wg_peers_parser.add_argument('--raw', action='store_true', help='Show raw API response for debugging')
    
    wg_servers_parser = wg_subparsers.add_parser('servers', help='List WireGuard servers')
    wg_servers_parser.add_argument('--site', help='Site key (uses current site if not specified)')
    wg_servers_parser.add_argument('--page', type=int, default=1, help='Page number')
    wg_servers_parser.add_argument('--page-size', type=int, default=10, help='Items per page')
    wg_servers_parser.add_argument('--raw', action='store_true', help='Show raw API response for debugging')
    
    wg_insights_parser = wg_subparsers.add_parser('insights', help='Show WireGuard connection insights')
    wg_insights_parser.add_argument('--site', help='Site key (uses current site if not specified)')
    wg_insights_parser.add_argument('--page', type=int, default=1, help='Page number')
    wg_insights_parser.add_argument('--page-size', type=int, default=10, help='Items per page')
    wg_insights_parser.add_argument('--server-filter', type=int, default=0, help='Server filter (0 for all)')
    wg_insights_parser.add_argument('--raw', action='store_true', help='Show raw API response for debugging')
    
    wg_summary_parser = wg_subparsers.add_parser('summary', help='Show WireGuard summary')
    wg_summary_parser.add_argument('--site', help='Site key (uses current site if not specified)')
    
    # WireGuard peer management
    wg_peer_parser = wg_subparsers.add_parser('peer', help='WireGuard peer management')
    wg_peer_subparsers = wg_peer_parser.add_subparsers(dest='wg_peer_command', help='Peer commands')
    
    wg_peer_create_parser = wg_peer_subparsers.add_parser('create', help='Create a new WireGuard peer')
    wg_peer_create_parser.add_argument('name', help='Peer name')
    wg_peer_create_parser.add_argument('--interface-id', required=True, help='WireGuard interface ID')
    wg_peer_create_parser.add_argument('--public-key', required=True, help='Peer public key')
    wg_peer_create_parser.add_argument('--endpoint', required=True, help='Peer endpoint IP or hostname')
    wg_peer_create_parser.add_argument('--endpoint-port', type=int, required=True, help='Peer endpoint port')
    wg_peer_create_parser.add_argument('--allow-address', nargs='+', required=True, help='Allowed IP addresses (space separated)')
    wg_peer_create_parser.add_argument('--keep-alive', type=int, default=25, help='Keep alive interval (seconds)')
    wg_peer_create_parser.add_argument('--status', action='store_true', default=True, help='Enable peer (default: enabled)')
    wg_peer_create_parser.add_argument('--site', help='Site key (uses current site if not specified)')

    wg_peer_delete_parser = wg_peer_subparsers.add_parser('delete', help='Delete a WireGuard peer')
    wg_peer_delete_parser.add_argument('name', help='Peer name')
    wg_peer_delete_parser.add_argument('--site', help='Site key (uses current site if not specified)')

    wg_peer_enable_parser = wg_peer_subparsers.add_parser('enable', help='Enable a WireGuard peer')
    wg_peer_enable_parser.add_argument('name', help='Peer name')
    wg_peer_enable_parser.add_argument('--site', help='Site key (uses current site if not specified)')
    
    wg_peer_disable_parser = wg_peer_subparsers.add_parser('disable', help='Disable a WireGuard peer')
    wg_peer_disable_parser.add_argument('name', help='Peer name')
    wg_peer_disable_parser.add_argument('--site', help='Site key (uses current site if not specified)')
    
    wg_peer_status_parser = wg_peer_subparsers.add_parser('status', help='Check WireGuard peer status')
    wg_peer_status_parser.add_argument('name', help='Peer name')
    wg_peer_status_parser.add_argument('--site', help='Site key (uses current site if not specified)')
    
    wg_peer_restart_parser = wg_peer_subparsers.add_parser('restart', help='Restart a WireGuard peer')
    wg_peer_restart_parser.add_argument('name', help='Peer name')
    wg_peer_restart_parser.add_argument('--site', help='Site key (uses current site if not specified)')
    
    wg_peer_list_parser = wg_peer_subparsers.add_parser('list', help='List all WireGuard peers with status')
    wg_peer_list_parser.add_argument('--site', help='Site key (uses current site if not specified)')
    wg_peer_list_parser.add_argument('--enabled-only', action='store_true', help='Show only enabled peers')
    wg_peer_list_parser.add_argument('--disabled-only', action='store_true', help='Show only disabled peers')
    
    # Alerts command
    alerts_parser = subparsers.add_parser('alerts', help='Show recent alerts')
    alerts_parser.add_argument('--limit', type=int, default=10, help='Number of alerts to show')
    
    # Find commands
    find_parser = subparsers.add_parser('find', help='Find devices or clients')
    find_subparsers = find_parser.add_subparsers(dest='find_command', help='Find commands')
    
    find_device_parser = find_subparsers.add_parser('device', help='Find device by name')
    find_device_parser.add_argument('name', help='Device name, MAC address, or model')
    find_device_parser.add_argument('--search-type', choices=['exact', 'partial', 'fuzzy', 'mac', 'model'], 
                                   default='fuzzy', help='Search method (default: fuzzy)')
    find_device_parser.add_argument('--limit', type=int, default=10, help='Maximum results to show')

    find_client_parser = find_subparsers.add_parser('client', help='Find client by name')
    find_client_parser.add_argument('name', help='Client name, MAC address, or IP')
    find_client_parser.add_argument('--active-only', action='store_true', default=True, help='Search only active clients')
    find_client_parser.add_argument('--all', action='store_true', help='Search all clients (active and inactive)')
    find_client_parser.add_argument('--search-type', choices=['exact', 'partial', 'fuzzy', 'mac', 'ip'], 
                                default='fuzzy', help='Search method (default: fuzzy)')
    find_client_parser.add_argument('--limit', type=int, default=10, help='Maximum results to show')

    # Custom Actions command
    actions_parser = subparsers.add_parser('actions', help='Execute custom actions', aliases=['action'])
    actions_subparsers = actions_parser.add_subparsers(dest='action_command', help='Custom action commands')

    for name, action_obj in CUSTOM_ACTIONS.items():
        sub_parser = actions_subparsers.add_parser(name, help=action_obj.description)
        if name == 'vpn-bulk-restart':
            sub_parser.add_argument('--force', action='store_true', help='Skip confirmation prompts')

    # OpenAPI v1 Client-to-Site VPN (separate backend/auth)
    add_vpn_client_subparser(subparsers)

    return parser

def main():
    load_env()
    parser = create_parser()
    args = parser.parse_args()

    # Scaffold the user config file, no controller/credentials needed
    if args.command == 'init':
        path, created = init_config()
        if created:
            print(f"Created {path}\nEdit it with your controller URL + credentials, then run: omada sites")
        else:
            print(f"Config already exists: {path}")
        return 0

    # v1 OpenAPI VPN client subcommand uses its own OAuth2 auth + logging
    if args.command == 'vpn-client':
        return run_vpn_client(args)

    # Setup logging first
    setup_logging(getattr(args, 'debug', False))
    logger = logging.getLogger('omada_api')

    if not args.command:
        parser.print_help()
        return

    # Get configuration
    config = get_config()

    # Override with command line arguments
    url = args.url or config['url']
    username = args.username or config['username']
    password = args.password or config['password']

    if not (url and username and password):
        print(config_hint(), file=sys.stderr)
        return 1

    try:
        # Create controller connection (no explicit connection needed)
        controller = create_controller(url, username, password, args.debug)
        
        # Load sites immediately for better UX
        controller.get_sites()
        
        # Set site if specified
        if args.site:
            if not controller.set_current_site(args.site):
                logger.error(f"Site '{args.site}' not found")
                return
        
        # Handle clients --all flag
        if hasattr(args, 'all') and args.all:
            args.active_only = False
        
        # Execute command
        if args.command == 'sites':
            cmd_sites(controller, args)
        elif args.command == 'summary':
            cmd_summary(controller, args)
        elif args.command == 'devices':
            cmd_devices(controller, args)
        elif args.command == 'clients':
            cmd_clients(controller, args)
        elif args.command == 'networks':
            cmd_networks(controller, args)
        elif args.command == 'ssids':
            cmd_ssids(controller, args)
        elif args.command == 'groups':
            cmd_groups(controller, args)
        elif args.command == 'acl':
            if args.acl_command == 'create':
                cmd_acl_create(controller, args)
            elif args.acl_command == 'edit':
                cmd_acl_edit(controller, args)
            elif args.acl_command in ('list', None):
                cmd_acl(controller, args)
            else:
                parser.parse_args(['acl', '--help'])
        elif args.command == 'mdns':
            cmd_mdns(controller, args)
        elif args.command == 'group':
            if args.group_command == 'set-mask':
                cmd_group_set_mask(controller, args)
            else:
                parser.parse_args(['group', '--help'])
        elif args.command == 'dhcp':
            if args.dhcp_command == 'reserve':
                cmd_dhcp_reserve(controller, args)
            else:
                parser.parse_args(['dhcp', '--help'])
        elif args.command == 'vpn':
            if args.vpn_command == 'list':
                cmd_vpn_list(controller, args)
            elif args.vpn_command == 'tunnels':
                cmd_vpn_tunnels(controller, args)
            elif args.vpn_command == 'enable':
                cmd_vpn_enable(controller, args)
            elif args.vpn_command == 'disable':
                cmd_vpn_disable(controller, args)
            elif args.vpn_command == 'status':
                cmd_vpn_status(controller, args)
            elif args.vpn_command == 'restart':
                cmd_vpn_restart(controller, args)
            else:
                parser.parse_args(['vpn', '--help'])
        elif args.command == 'wireguard':
            if args.wg_command == 'peers':
                cmd_wireguard_peers(controller, args)
            elif args.wg_command == 'servers':
                cmd_wireguard_servers(controller, args)
            elif args.wg_command == 'insights':
                cmd_wireguard_insights(controller, args)
            elif args.wg_command == 'summary':
                cmd_wireguard_summary(controller, args)
            elif args.wg_command == 'peer':
                if args.wg_peer_command == 'enable':
                    cmd_wireguard_peer_enable(controller, args)
                elif args.wg_peer_command == 'disable':
                    cmd_wireguard_peer_disable(controller, args)
                elif args.wg_peer_command == 'status':
                    cmd_wireguard_peer_status(controller, args)
                elif args.wg_peer_command == 'restart':
                    cmd_wireguard_peer_restart(controller, args)
                elif args.wg_peer_command == 'list':
                    cmd_wireguard_peer_list(controller, args)
                elif args.wg_peer_command == 'create':
                    cmd_wireguard_peer_create(controller, args)
                elif args.wg_peer_command == 'delete':
                    cmd_wireguard_peer_delete(controller, args)
                else:
                    parser.parse_args(['wireguard', 'peer', '--help'])
            else:
                parser.parse_args(['wireguard', '--help'])
        elif args.command == 'alerts':
            cmd_alerts(controller, args)
        elif args.command == 'find':
            if args.find_command == 'device':
                cmd_find_device(controller, args)
            elif args.find_command == 'client':
                cmd_find_client(controller, args)
            else:
                parser.parse_args(['find', '--help'])
        elif args.command in ['actions', 'action']:
            if hasattr(args, 'action_command') and args.action_command:
                cmd_custom_action(controller, args)
            else:
                parser.parse_args([args.command, '--help'])
        
    except ConnectionError as e:
        logger.error(f"Connection error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Operation cancelled")
        sys.exit(1)
    except Exception as e:
        if args.debug:
            import traceback
            logger.error("Exception occurred:", exc_info=True)
        else:
            logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
