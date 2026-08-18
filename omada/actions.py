"""Predefined custom actions (multi-step operations)."""
import logging


class CustomAction:
    """Base class for custom actions"""
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def execute(self, controller, args) -> bool:
        """Execute the custom action. Return True if successful."""
        raise NotImplementedError("Subclasses must implement execute method")

class VPNHealthCheckAction(CustomAction):
    """Check enabled VPNs for active tunnels and restart if none found"""
    
    def __init__(self):
        super().__init__(
            "vpn-health-check",
            "Check enabled VPNs for active tunnels, restart if no tunnels found"
        )
    
    def execute(self, controller, args) -> bool:
        logger = logging.getLogger('omada_vpn')
        logger.info("🔍 Starting VPN Health Check...")
        
        # Get all VPN configurations
        vpns = controller.get_vpn_configs(args.site)
        if not vpns:
            logger.error("❌ No VPN configurations found")
            return False
        
        # Filter enabled VPNs and separate client vs server VPNs
        enabled_vpns = [vpn for vpn in vpns if vpn.get('status', False)]
        if not enabled_vpns:
            logger.info("ℹ️  No enabled VPNs found")
            return True
        
        # Separate client VPNs from server VPNs
        client_vpns = []
        server_vpns = []
        
        for vpn in enabled_vpns:
            vpn_name = vpn.get('name', 'Unknown')
            
            is_client_vpn = False
            
            # Primary check: clientVpnType1 = 1 means it's a client VPN
            client_vpn_type1 = vpn.get('clientVpnType1', 0)
            has_remote_ip = vpn.get('remoteIp') and vpn.get('remoteIp') != 'not_present' and vpn.get('remoteIp') != ''
            
            if client_vpn_type1 == 1 and has_remote_ip:
                is_client_vpn = True
                logger.debug(f"  → Client VPN (clientVpnType1=1, connects to {vpn.get('remoteIp')})")
            elif client_vpn_type1 == 0:
                is_client_vpn = False
                logger.debug(f"  → Server VPN (clientVpnType1=0, accepts incoming connections)")
            else:
                # Fallback logic for edge cases
                logger.debug(f"  → Unknown VPN type, treating as server (clientVpnType1={client_vpn_type1})")
                is_client_vpn = False
            
            if is_client_vpn:
                client_vpns.append(vpn)
            else:
                server_vpns.append(vpn)
        
        logger.info(f"📋 Found {len(enabled_vpns)} enabled VPN(s):")
        if client_vpns:
            logger.info(f"  🔗 Client VPNs ({len(client_vpns)}):")
            for vpn in client_vpns:
                logger.info(f"    - {vpn.get('name', 'Unknown')}")
        if server_vpns:
            logger.info(f"  🖥️  Server VPNs ({len(server_vpns)}) - skipping health check:")
            for vpn in server_vpns:
                logger.info(f"    - {vpn.get('name', 'Unknown')} (server VPNs don't need active tunnels)")
        
        if not client_vpns:
            logger.info("ℹ️  No client VPNs found to check")
            return True
        
        # Get active CLIENT tunnels only (filters.server=1)
        client_tunnels = controller.get_vpn_tunnels(args.site, server_type=1)
        active_client_tunnel_names = [tunnel['vpnName'] for tunnel in client_tunnels]
        
        logger.info(f"🔗 Found {len(client_tunnels)} active client tunnel(s):")
        for tunnel in client_tunnels:
            logger.info(f"  - {tunnel['vpnName']}")
        
        # Check each enabled CLIENT VPN for active tunnels
        vpns_to_restart = []
        for vpn in client_vpns:
            vpn_name = vpn.get('name', 'Unknown')
            if vpn_name not in active_client_tunnel_names:
                vpns_to_restart.append(vpn_name)
                logger.warning(f"⚠️  Client VPN '{vpn_name}' is enabled but has no active tunnel")
        
        if not vpns_to_restart:
            logger.info("✅ All enabled client VPNs have active tunnels - no action needed")
            return True
        
        # Restart VPNs without tunnels
        logger.info(f"🔄 Restarting {len(vpns_to_restart)} VPN(s) without active tunnels...")
        
        success_count = 0
        for vpn_name in vpns_to_restart:
            logger.info(f"🔄 Restarting VPN: {vpn_name}")
            if self._restart_vpn_with_status(controller, vpn_name, args.site):
                success_count += 1
                logger.info(f"✅ Successfully restarted '{vpn_name}'")
            else:
                logger.error(f"❌ Failed to restart '{vpn_name}'")
        
        logger.info(f"📊 Health Check Summary:")
        logger.info(f"  - Total enabled VPNs: {len(enabled_vpns)}")
        logger.info(f"  - Client VPNs checked: {len(client_vpns)}")
        logger.info(f"  - Server VPNs skipped: {len(server_vpns)}")
        logger.info(f"  - Active client tunnels: {len(client_tunnels)}")
        logger.info(f"  - Client VPNs restarted: {success_count}/{len(vpns_to_restart)}")
        
        return success_count == len(vpns_to_restart)
    
    def _restart_vpn_with_status(self, controller, vpn_name: str, site_key=None) -> bool:
        """Restart VPN with detailed status reporting"""
        import time
        
        logger = logging.getLogger('omada_vpn')
        try:
            logger.debug("Restarting VPN...")
            # Disable
            if not controller.toggle_vpn(vpn_name, False, site_key):
                logger.error(f"  ❌ Failed to disable '{vpn_name}'")
                return False
            
            # Wait
            time.sleep(3)
            
            # Enable
            if not controller.toggle_vpn(vpn_name, True, site_key):
                logger.error(f"  ❌ Failed to enable '{vpn_name}'")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"  ❌ Error restarting '{vpn_name}': {str(e)}")
            return False

class VPNBulkRestartAction(CustomAction):
    """Restart all enabled VPNs"""
    
    def __init__(self):
        super().__init__(
            "vpn-bulk-restart",
            "Restart all enabled VPNs with delay between each"
        )
    
    def execute(self, controller, args) -> bool:
        import time
        
        logger = logging.getLogger('omada_vpn')
        logger.info("🔄 Starting VPN Bulk Restart...")
        
        # Get enabled VPNs
        vpns = controller.get_vpn_configs(args.site)
        enabled_vpns = [vpn for vpn in vpns if vpn.get('status', False)]
        
        if not enabled_vpns:
            logger.info("ℹ️  No enabled VPNs found")
            return True
        
        logger.info(f"📋 Found {len(enabled_vpns)} enabled VPN(s) to restart:")
        for vpn in enabled_vpns:
            logger.info(f"  - {vpn.get('name', 'Unknown')}")
        
        # Confirm action
        if not getattr(args, 'force', False):
            response = input(f"\nRestart {len(enabled_vpns)} VPN(s)? [y/N]: ")
            if response.lower() != 'y':
                logger.info("Operation cancelled")
                return False
        
        # Restart each VPN
        success_count = 0
        for i, vpn in enumerate(enabled_vpns, 1):
            vpn_name = vpn.get('name', 'Unknown')
            logger.info(f"[{i}/{len(enabled_vpns)}] Restarting '{vpn_name}'...")
            
            if VPNHealthCheckAction()._restart_vpn_with_status(controller, vpn_name, args.site):
                success_count += 1
            
            # Add delay between restarts (except for the last one)
            if i < len(enabled_vpns):
                logger.info("  Waiting 5 seconds before next restart...")
                time.sleep(5)
        
        logger.info(f"📊 Bulk Restart Summary:")
        logger.info(f"  - Total VPNs: {len(enabled_vpns)}")
        logger.info(f"  - Successfully restarted: {success_count}")
        logger.info(f"  - Failed: {len(enabled_vpns) - success_count}")
        
        return success_count == len(enabled_vpns)

class NetworkStatusAction(CustomAction):
    """Comprehensive network status report"""
    
    def __init__(self):
        super().__init__(
            "network-status",
            "Generate comprehensive network status report"
        )
    
    def execute(self, controller, args) -> bool:
        logger = logging.getLogger('omada_api')
        logger.info("📊 Generating Network Status Report...")
        
        # Network Summary
        logger.info("=== Network Summary ===")
        summary = controller.get_network_summary(args.site)
        if summary:
            for key, value in summary.items():
                logger.info(f"  {key.replace('_', ' ').title()}: {value}")
        
        # VPN Status
        logger.info("=== VPN Status ===")
        vpns = controller.get_vpn_configs(args.site)
        tunnels = controller.get_vpn_tunnels(args.site)
        
        enabled_count = sum(1 for vpn in vpns if vpn.get('status', False))
        logger.info(f"  Total VPNs: {len(vpns)}")
        logger.info(f"  Enabled: {enabled_count}")
        logger.info(f"  Active Tunnels: {len(tunnels)}")
        
        # Recent Alerts
        logger.info("=== Recent Alerts (Last 5) ===")
        alerts = controller.get_alerts_list(args.site, 5)
        if alerts:
            for alert in alerts:
                logger.info(f"  - {alert.get('msg', 'Unknown')} (Level: {alert.get('level', 'Unknown')})")
        else:
            logger.info("  No recent alerts")
        
        # Device Status
        logger.info("=== Device Summary ===")
        devices = controller.get_devices_list(args.site)
        if devices:
            online_devices = sum(1 for device in devices if device.get('status') == 1)
            logger.info(f"  Total Devices: {len(devices)}")
            logger.info(f"  Online: {online_devices}")
            logger.info(f"  Offline: {len(devices) - online_devices}")
        
        return True

# Custom Actions Registry
CUSTOM_ACTIONS = {
    'vpn-health-check': VPNHealthCheckAction(),
    'vpn-bulk-restart': VPNBulkRestartAction(),
    'network-status': NetworkStatusAction(),
}

def cmd_custom_action(controller, args):
    """Execute a custom action"""
    logger = logging.getLogger('omada_api')
    action_name = args.action_command
    
    if action_name not in CUSTOM_ACTIONS:
        logger.error(f"Unknown custom action: {action_name}")
        logger.info(f"Available actions: {', '.join(CUSTOM_ACTIONS.keys())}")
        return
    
    action = CUSTOM_ACTIONS[action_name]
    logger.info(f"🚀 Executing custom action: {action.name}")
    
    try:
        success = action.execute(controller, args)
        if success:
            logger.info(f"✅ Custom action '{action_name}' completed successfully")
        else:
            logger.error(f"❌ Custom action '{action_name}' failed")
    except Exception as e:
        logger.error(f"💥 Error executing custom action '{action_name}': {str(e)}")

