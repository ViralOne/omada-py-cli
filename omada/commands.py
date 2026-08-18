"""CLI command handlers (cmd_* functions). Each takes (controller, args)."""
import logging


def cmd_sites(controller, args):
    """List all sites"""
    logger = logging.getLogger('omada_api')
    sites = controller.get_sites()
    if not sites:
        logger.info("No sites found")
        return
    
    logger.info("Available Sites:")
    for site in sites:
        current = " (CURRENT)" if site['id'] == controller.current_site_key else ""
        logger.info(f"  - {site['name']} ({site['id']}){current}")

def cmd_summary(controller, args):
    """Show network summary"""
    logger = logging.getLogger('omada_api')
    summary = controller.get_network_summary(args.site)
    if not summary:
        logger.info("No summary data available")
        return
    
    logger.info("Network Summary:")
    for key, value in summary.items():
        logger.info(f"  {key.replace('_', ' ').title()}: {value}")

def cmd_devices(controller, args):
    """List devices"""
    logger = logging.getLogger('omada_api')
    devices = controller.get_devices_list(args.site)
    if not devices:
        logger.info("No devices found")
        return
    
    logger.info(f"Devices ({len(devices)} total):")
    for device in devices:
        logger.info(f"  - {device['name']} ({device['mac']}) - {device['model']} - Status: {device['status']}")

def cmd_clients(controller, args):
    """List clients"""
    logger = logging.getLogger('omada_api')
    clients = controller.get_clients_list(args.site, args.active_only)
    if not clients:
        logger.info("No clients found")
        return
    
    status_text = "Active" if args.active_only else "All"
    logger.info(f"{status_text} Clients ({len(clients)} total):")
    for client in clients[:args.limit]:
        name = client.get('name', 'Unknown')
        mac = client.get('mac', 'Unknown')
        ip = client.get('ip', 'No IP')
        logger.info(f"  - {name} ({mac}) - {ip}")

def cmd_vpn_tunnels(controller, args):
    """Show VPN tunnel statistics"""
    logger = logging.getLogger('omada_vpn')
    tunnels = controller.get_vpn_tunnels(args.site)
    if not tunnels:
        logger.info("No active VPN tunnels")
        return
    
    logger.info("Active VPN Tunnels:")
    for tunnel in tunnels:
        tunnel_type = tunnel.get('_tunnel_type', 'unknown')
        logger.info(f"  - {tunnel['vpnName']} ({tunnel['interfaceName']}) [{tunnel_type} tunnel]")
        logger.info(f"    {tunnel['localIp']} -> {tunnel['remoteIp']} | Uptime: {tunnel['uptime']}")
        logger.info(f"    Down: {tunnel['downPkts']} pkts, {tunnel['downBytes']} bytes")
        logger.info(f"    Up: {tunnel['upPkts']} pkts, {tunnel['upBytes']} bytes")

def cmd_vpn_list(controller, args):
    """List VPN configurations"""
    logger = logging.getLogger('omada_vpn')
    vpns = controller.get_vpn_configs(args.site)
    if not vpns:
        logger.info("No VPN configurations found")
        return
    
    logger.info("VPN Configurations:")
    for vpn in vpns:
        status = "✓ Enabled" if vpn.get('status', False) else "✗ Disabled"
        logger.info(f"  - {vpn.get('name', 'Unknown')} - {status}")

def cmd_vpn_enable(controller, args):
    """Enable a VPN"""
    logger = logging.getLogger('omada_vpn')
    if controller.toggle_vpn(args.name, True, args.site):
        logger.info(f"VPN '{args.name}' enabled successfully")
    else:
        logger.error(f"Failed to enable VPN '{args.name}'")

def cmd_vpn_disable(controller, args):
    """Disable a VPN"""
    logger = logging.getLogger('omada_vpn')
    if controller.toggle_vpn(args.name, False, args.site):
        logger.info(f"VPN '{args.name}' disabled successfully")
    else:
        logger.error(f"Failed to disable VPN '{args.name}'")

def cmd_vpn_status(controller, args):
    """Check VPN status"""
    logger = logging.getLogger('omada_vpn')
    status = controller.get_vpn_status(args.name, args.site)
    if status is None:
        logger.warning(f"VPN '{args.name}' not found")
    else:
        logger.info(f"VPN '{args.name}' is {'enabled' if status else 'disabled'}")

def cmd_vpn_restart(controller, args):
    """Restart a VPN (disable, wait 2 seconds, enable)"""
    import time
    
    logger = logging.getLogger('omada_vpn')
    logger.info(f"Restarting VPN '{args.name}'...")
    
    # First, disable the VPN
    if not controller.toggle_vpn(args.name, False, args.site):
        logger.error(f"Failed to disable VPN '{args.name}'")
        return
    
    # Wait 2 seconds
    time.sleep(2)
    
    # Enable the VPN
    if controller.toggle_vpn(args.name, True, args.site):
        logger.info(f"VPN '{args.name}' restarted successfully")
    else:
        logger.error(f"Failed to enable VPN '{args.name}' after restart")

def cmd_alerts(controller, args):
    """Show recent alerts"""
    logger = logging.getLogger('omada_api')
    alerts = controller.get_alerts_list(args.site, args.limit)
    if not alerts:
        logger.info("No recent alerts")
        return
    
    logger.info(f"Recent Alerts ({len(alerts)} total):")
    for alert in alerts:
        logger.info(f"  - {alert.get('msg', 'Unknown')} (Level: {alert.get('level', 'Unknown')})")

def cmd_networks(controller, args):
    """List wired networks (VLANs)"""
    logger = logging.getLogger('omada_api')
    networks = controller.get_networks(args.site)
    if not networks:
        logger.info("No networks found")
        return

    logger.info(f"Networks ({len(networks)} total):")
    for net in networks:
        vlan = net.get('vlan', 'N/A')
        subnet = net.get('gatewaySubnet', 'N/A')
        acl = " [ACL]" if net.get('accessControlRule') else ""
        iso = " [isolated]" if net.get('isolation') else ""
        primary = " (primary)" if net.get('primary') else ""
        logger.info(f"  - {net.get('name', 'Unknown')} - VLAN {vlan} - {subnet}{acl}{iso}{primary}")
        logger.info(f"    id: {net.get('id')}")

def cmd_ssids(controller, args):
    """List SSIDs"""
    logger = logging.getLogger('omada_api')
    ssids = controller.get_ssids(getattr(args, 'wlan_id', None), args.site)
    if not ssids:
        logger.info("No SSIDs found")
        return

    logger.info(f"SSIDs ({len(ssids)} total):")
    for ssid in ssids:
        vlan = ssid.get('vlanId') if ssid.get('vlanEnable') else 'untagged'
        guest = " [guest]" if ssid.get('guestNetEnable') else ""
        band = ssid.get('band', 'N/A')
        logger.info(f"  - {ssid.get('name', 'Unknown')} - VLAN {vlan} - band {band}{guest}")
        logger.info(f"    id: {ssid.get('id')}")

def cmd_groups(controller, args):
    """List IP / domain groups"""
    logger = logging.getLogger('omada_api')
    groups = controller.get_groups(args.site)
    if not groups:
        logger.info("No groups found")
        return

    logger.info(f"Groups ({len(groups)} total):")
    for group in groups:
        if group.get('ipList'):
            rendered = ', '.join(f"{e['ip']}/{e['mask']}" for e in group['ipList'])
        elif group.get('domainName'):
            rendered = ', '.join(group['domainName'])
        elif group.get('ipv6List'):
            rendered = ', '.join(f"{e['ip']}/{e['prefix']}" for e in group['ipv6List'])
        else:
            rendered = "(empty)"
        builtin = " [built-in]" if group.get('buildIn') else ""
        logger.info(f"  - {group.get('name', 'Unknown')}{builtin}: {rendered}")
        logger.info(f"    groupId: {group.get('groupId')}")

def cmd_acl(controller, args):
    """List ACL rules"""
    logger = logging.getLogger('omada_api')
    acl_type = getattr(args, 'type', 'gateway')
    acls = controller.get_acls(acl_type, args.site)
    if not acls:
        logger.info(f"No {acl_type} ACL rules found")
        return

    logger.info(f"{acl_type.capitalize()} ACL rules ({len(acls)} total):")
    for acl in acls:
        policy = "PERMIT" if acl.get('policy') == 1 else "DENY"
        status = "enabled" if acl.get('status') else "disabled"
        logger.info(f"  [{acl.get('index')}] {acl.get('name', 'Unknown')} - {policy} - {status}")
        logger.info(f"      srcType={acl.get('sourceType')} src={acl.get('sourceIds')}")
        logger.info(f"      dstType={acl.get('destinationType')} dst={acl.get('destinationIds')}")
        logger.info(f"      id: {acl.get('id')}")

def cmd_find_device(controller, args):
    """Find devices using advanced search"""
    search_type = getattr(args, 'search_type', 'fuzzy')
    limit = getattr(args, 'limit', 10)
    
    logger = logging.getLogger('omada_api')
    
    # Try exact match first
    if search_type == 'fuzzy':
        exact_device = controller.find_device_by_name(args.name, args.site)
        if exact_device:
            logger.info(f"🎯 Exact match found:")
            logger.info(f"  Name: {exact_device['name']}")
            logger.info(f"  MAC: {exact_device['mac']}")
            logger.info(f"  Model: {exact_device['model']}")
            logger.info(f"  Status: {exact_device['status']}")
            return
    
    # Use advanced search
    results = controller.search_devices(args.name, args.site, search_type, limit)
    
    if not results:
        logger.info(f"No devices found matching '{args.name}' using {search_type} search")
        if search_type != 'fuzzy':
            logger.info("💡 Try using fuzzy search: --search-type fuzzy")
        return
    
    if len(results) == 1:
        device = results[0]
        logger.info(f"🎯 Device found ({device['_match_reason']}):")
        logger.info(f"  Name: {device['name']}")
        logger.info(f"  MAC: {device['mac']}")
        logger.info(f"  Model: {device['model']}")
        logger.info(f"  Status: {device['status']}")
    else:
        logger.info(f"🔍 Found {len(results)} devices matching '{args.name}':")
        for i, device in enumerate(results, 1):
            status_icon = "🟢" if device.get('status') == 1 else "🔴"
            logger.info(f"  {i}. {device['name']} {status_icon}")
            logger.info(f"     MAC: {device['mac']} | Model: {device['model']}")
            logger.info(f"     Match: {device['_match_reason']} (score: {device['_match_score']})")

def cmd_find_client(controller, args):
    """Find clients using advanced search"""
    logger = logging.getLogger('omada_api')
    search_type = getattr(args, 'search_type', 'fuzzy')
    limit = getattr(args, 'limit', 10)
    
    # Try exact match first
    if search_type == 'fuzzy':
        exact_client = controller.find_client_by_name(args.name, args.site, args.active_only)
        if exact_client:
            logger.info(f"🎯 Exact match found:")
            logger.info(f"  Name: {exact_client.get('name', 'Unknown')}")
            logger.info(f"  MAC: {exact_client.get('mac', 'Unknown')}")
            logger.info(f"  IP: {exact_client.get('ip', 'No IP')}")
            return
    
    # Use advanced search
    results = controller.search_clients(args.name, args.site, args.active_only, search_type, limit)
    
    if not results:
        status_text = "active" if args.active_only else "all"
        logger.info(f"No {status_text} clients found matching '{args.name}' using {search_type} search")
        if args.active_only:
            logger.info("💡 Try searching all clients: --all")
        if search_type != 'fuzzy':
            logger.info("💡 Try using fuzzy search: --search-type fuzzy")
        return
    
    if len(results) == 1:
        client = results[0]
        logger.info(f"🎯 Client found ({client['_match_reason']}):")
        logger.info(f"  Name: {client.get('name', 'Unknown')}")
        logger.info(f"  MAC: {client.get('mac', 'Unknown')}")
        logger.info(f"  IP: {client.get('ip', 'No IP')}")
    else:
        status_text = "active" if args.active_only else "all"
        logger.info(f"🔍 Found {len(results)} {status_text} clients matching '{args.name}':")
        for i, client in enumerate(results, 1):
            name = client.get('name', 'Unknown')
            mac = client.get('mac', 'Unknown')
            ip = client.get('ip', 'No IP')
            logger.info(f"  {i}. {name}")
            logger.info(f"     MAC: {mac} | IP: {ip}")
            logger.info(f"     Match: {client['_match_reason']} (score: {client['_match_score']})")


def cmd_wireguard_peers(controller, args):
    """List WireGuard peers"""
    logger = logging.getLogger('omada_vpn')
    peers = controller.get_wireguard_peers(args.site, getattr(args, 'page', 1), getattr(args, 'page_size', 10))
    if not peers:
        logger.info("No WireGuard peers found")
        return
    
    logger.info(f"WireGuard Peers ({len(peers)} total):")
    
    # Show raw data if requested
    if getattr(args, 'raw', False):
        logger.info("Raw API Response:")
        for i, peer in enumerate(peers, 1):
            logger.info(f"  Peer {i}: {peer}")
        return
    
    for peer in peers:
        # Use the actual field names from the API response
        enabled = peer.get('status', False)
        status = "✓ Enabled" if enabled else "✗ Disabled"
        
        logger.info(f"  - {peer.get('name', 'Unknown')} - {status}")
        logger.info(f"    Interface: {peer.get('interfaceName', 'Unknown')}")
        public_key = peer.get('publicKey') or 'N/A'
        logger.info(f"    Public Key: {public_key[:20]}...")
        
        # Show allowed addresses (this is the correct field name)
        allowed_addresses = peer.get('allowAddress', [])
        if allowed_addresses:
            logger.info(f"    Allowed IPs: {', '.join(allowed_addresses)}")
        else:
            logger.info(f"    Allowed IPs: N/A")
        
        # Show keep alive setting
        keep_alive = peer.get('keepAlive')
        if keep_alive:
            logger.info(f"    Keep Alive: {keep_alive}s")
        
        logger.info("")  # Empty line between peers

def cmd_wireguard_servers(controller, args):
    """List WireGuard servers"""
    logger = logging.getLogger('omada_vpn')
    servers = controller.get_wireguard_servers(args.site, getattr(args, 'page', 1), getattr(args, 'page_size', 10))
    if not servers:
        logger.info("No WireGuard servers found")
        return
    
    logger.info(f"WireGuard Servers ({len(servers)} total):")
    
    # Show raw data if requested
    if getattr(args, 'raw', False):
        logger.info("Raw API Response:")
        for i, server in enumerate(servers, 1):
            logger.info(f"  Server {i}: {server}")
        return
    
    for server in servers:
        # Use the actual field names from the API response
        enabled = server.get('status', False)
        status = "✓ Enabled" if enabled else "✗ Disabled"
        
        logger.info(f"  - {server.get('name', 'Unknown')} - {status}")
        
        # Show server details using actual field names
        listen_port = server.get('listenPort')
        if listen_port:
            logger.info(f"    Listen Port: {listen_port}")
        
        public_key = server.get('publicKey')
        if public_key:
            logger.info(f"    Public Key: {public_key[:20]}...")
        
        # Show local IP (external endpoint)
        local_ip = server.get('localIp')
        if local_ip:
            logger.info(f"    External IP: {local_ip}")
        
        # Show ID
        server_id = server.get('id')
        if server_id:
            logger.info(f"    Interface-id: {server_id}")
        
        logger.info("")  # Empty line between servers


def cmd_wireguard_peer_create(controller, args):
    """Create a new WireGuard peer"""
    logger = logging.getLogger('omada_vpn')
    peer_config = {
        "name": args.name,
        "interfaceId": args.interface_id,
        "publicKey": args.public_key,
        "endPoint": args.endpoint,
        "endPointPort": args.endpoint_port,
        "allowAddress": args.allow_address,
        "keepAlive": args.keep_alive,
        "status": args.status
    }
    logger.debug(f"Creating WireGuard peer with config: {peer_config}")
    if controller.create_wireguard_peer(peer_config, args.site):
        logger.info(f"WireGuard peer '{args.name}' created successfully")
    else:
        logger.error(f"Failed to create WireGuard peer '{args.name}'")

def cmd_wireguard_peer_delete(controller, args):
    """Delete a WireGuard peer by name"""
    logger = logging.getLogger('omada_vpn')
    peer = controller.get_wireguard_peer_by_name(args.name, args.site)
    if not peer:
        logger.error(f"WireGuard peer '{args.name}' not found")
        return
    peer_id = peer.get('id')
    if controller.delete_wireguard_peer(peer_id, args.site):
        logger.info(f"WireGuard peer '{args.name}' deleted successfully")
    else:
        logger.error(f"Failed to delete WireGuard peer '{args.name}'")

def cmd_wireguard_insights(controller, args):
    """Show WireGuard connection insights"""
    logger = logging.getLogger('omada_vpn')
    server_filter = getattr(args, 'server_filter', 0)
    insights = controller.get_wireguard_insights(args.site, getattr(args, 'page', 1), 
                                               getattr(args, 'page_size', 10), server_filter)
    if not insights:
        logger.info("No WireGuard connection insights available")
        return
    
    logger.info(f"WireGuard Connection Insights ({len(insights)} total):")
    
    # Show raw data if requested
    if getattr(args, 'raw', False):
        logger.info("Raw API Response:")
        for i, insight in enumerate(insights, 1):
            logger.info(f"  Connection {i}: {insight}")
        return
    
    for i, insight in enumerate(insights, 1):
        logger.info(f"  Connection {i}:")
        
        # Show all available fields for debugging
        if controller.debug:
            logger.debug(f"    Raw data: {insight}")
        
        # Use the actual field names from the API response
        peer_name = insight.get('name', 'Unknown')
        server_name = insight.get('interfaceName', 'Unknown')
        remote_ip = insight.get('remoteIp', 'N/A')
        remote_port = insight.get('remotePort', 'N/A')
        
        logger.info(f"    Peer: {peer_name}")
        logger.info(f"    Server: {server_name}")
        logger.info(f"    Remote Endpoint: {remote_ip}:{remote_port}")
        
        # Handle timestamp fields
        handshake = insight.get('lastHandshake', 'N/A')
        logger.info(f"    Last Handshake: {handshake}")
        
        # Handle transfer data with proper formatting
        down_bytes = insight.get('downBytes', 0)
        up_bytes = insight.get('upBytes', 0)
        
        def format_bytes(bytes_val):
            """Format bytes in human readable format"""
            if bytes_val == 0:
                return "0 B"
            
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if bytes_val < 1024.0:
                    return f"{bytes_val:.1f} {unit}"
                bytes_val /= 1024.0
            return f"{bytes_val:.1f} PB"
        
        logger.info(f"    Transfer - Down: {format_bytes(down_bytes)}, Up: {format_bytes(up_bytes)}")
        
        logger.info("")  # Empty line between connections

def cmd_wireguard_peer_enable(controller, args):
    """Enable a WireGuard peer"""
    logger = logging.getLogger('omada_vpn')
    if controller.toggle_wireguard_peer(args.name, True, args.site):
        logger.info(f"WireGuard peer '{args.name}' enabled successfully")
    else:
        logger.error(f"Failed to enable WireGuard peer '{args.name}'")

def cmd_wireguard_peer_disable(controller, args):
    """Disable a WireGuard peer"""
    logger = logging.getLogger('omada_vpn')
    if controller.toggle_wireguard_peer(args.name, False, args.site):
        logger.info(f"WireGuard peer '{args.name}' disabled successfully")
    else:
        logger.error(f"Failed to disable WireGuard peer '{args.name}'")

def cmd_wireguard_peer_status(controller, args):
    """Check WireGuard peer status"""
    logger = logging.getLogger('omada_vpn')
    peer = controller.get_wireguard_peer_by_name(args.name, args.site)
    if not peer:
        logger.warning(f"WireGuard peer '{args.name}' not found")
    else:
        status = "enabled" if peer.get('status', False) else "disabled"
        logger.info(f"WireGuard peer '{args.name}' is {status}")
        logger.info(f"  Public Key: {peer.get('publicKey', 'N/A')}")
        allowed = peer.get('allowAddress') or []
        logger.info(f"  Allowed IPs: {', '.join(allowed) if allowed else 'N/A'}")
        if peer.get('endPoint'):
            logger.info(f"  Endpoint: {peer.get('endPoint')}:{peer.get('endPointPort', '')}")

def cmd_wireguard_peer_restart(controller, args):
    """Restart a WireGuard peer (disable, wait 2 seconds, enable)"""
    import time
    
    logger = logging.getLogger('omada_vpn')
    logger.info(f"Restarting WireGuard peer '{args.name}'...")
    
    # First, disable the peer
    if not controller.toggle_wireguard_peer(args.name, False, args.site):
        logger.error(f"Failed to disable WireGuard peer '{args.name}'")
        return
    
    # Wait 2 seconds
    time.sleep(2)
    
    # Enable the peer
    if controller.toggle_wireguard_peer(args.name, True, args.site):
        logger.info(f"WireGuard peer '{args.name}' restarted successfully")
    else:
        logger.error(f"Failed to enable WireGuard peer '{args.name}' after restart")

def cmd_wireguard_peer_list(controller, args):
    """List WireGuard peers with filtering options"""
    logger = logging.getLogger('omada_vpn')
    peers = controller.get_wireguard_peers(args.site)
    if not peers:
        logger.info("No WireGuard peers found")
        return
    
    # Apply filters
    filtered_peers = peers
    if getattr(args, 'enabled_only', False):
        filtered_peers = [p for p in peers if p.get('status', False)]
    elif getattr(args, 'disabled_only', False):
        filtered_peers = [p for p in peers if not p.get('status', False)]
    
    if not filtered_peers:
        filter_text = "enabled" if getattr(args, 'enabled_only', False) else "disabled"
        logger.info(f"No {filter_text} WireGuard peers found")
        return
    
    # Count enabled/disabled
    enabled_count = sum(1 for p in peers if p.get('status', False))
    disabled_count = len(peers) - enabled_count
    
    logger.info(f"WireGuard Peers Summary: {enabled_count} enabled, {disabled_count} disabled")
    logger.info(f"Showing {len(filtered_peers)} peers:")
    
    for peer in filtered_peers:
        enabled = peer.get('status', False)
        status_icon = "🟢" if enabled else "🔴"
        status_text = "Enabled" if enabled else "Disabled"
        
        logger.info(f"  {status_icon} {peer.get('name', 'Unknown')} - {status_text}")
        logger.info(f"    Interface: {peer.get('interfaceName', 'Unknown')}")
        logger.info(f"    Allowed IPs: {', '.join(peer.get('allowAddress', []))}")
        logger.info(f"    Peer ID: {peer.get('id', 'Unknown')}")
        logger.info("")

def cmd_wireguard_summary(controller, args):
    """Show WireGuard summary with servers, peers, and connections"""
    logger = logging.getLogger('omada_vpn')
    
    logger.info("WireGuard Summary")
    logger.info("=" * 50)
    
    # Get servers
    servers = controller.get_wireguard_servers(args.site)
    if servers:
        enabled_servers = sum(1 for s in servers if s.get('status', False))
        logger.info(f"📡 Servers: {len(servers)} total, {enabled_servers} enabled")
        for server in servers:
            status_icon = "🟢" if server.get('status', False) else "🔴"
            logger.info(f"  {status_icon} {server.get('name', 'Unknown')} (Port: {server.get('listenPort', 'N/A')})")
    else:
        logger.info("📡 Servers: None found")
    
    logger.info("")
    
    # Get peers
    peers = controller.get_wireguard_peers(args.site)
    if peers:
        enabled_peers = sum(1 for p in peers if p.get('status', False))
        logger.info(f"👥 Peers: {len(peers)} total, {enabled_peers} enabled")
        for peer in peers:
            status_icon = "🟢" if peer.get('status', False) else "🔴"
            logger.info(f"  {status_icon} {peer.get('name', 'Unknown')}")
    else:
        logger.info("👥 Peers: None found")
    
    logger.info("")
    
    # Get active connections
    insights = controller.get_wireguard_insights(args.site)
    if insights:
        logger.info(f"🔗 Active Connections: {len(insights)}")
        for insight in insights:
            peer_name = insight.get('name', 'Unknown')
            last_handshake = insight.get('lastHandshake', 'N/A')
            logger.info(f"  🔗 {peer_name} - Last: {last_handshake}")
    else:
        logger.info("🔗 Active Connections: None")
    
    logger.info("")
    logger.info("=" * 50)

# Custom Actions System
