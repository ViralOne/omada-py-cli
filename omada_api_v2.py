#!/usr/bin/env python3

import requests
import json
import urllib3
import argparse
import sys
import os
import logging
from datetime import datetime
from urllib.parse import urljoin
from typing import Optional, Dict, List, Any
from dotenv import load_dotenv

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

class OmadaController:
    def __init__(self, base_url, username, password, debug=False):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False  # Skip SSL verification
        self.controller_id = None
        self.token = None
        self.debug = debug
        self.sites = []
        self.current_site_key = None
        self._authenticated = False
        
        # Set up logging
        self.logger = logging.getLogger('omada_api')
        self.vpn_logger = logging.getLogger('omada_vpn')
        
    def _debug_print(self, message):
        if self.debug:
            self.logger.debug(message)
        
    def connect(self) -> bool:
        """Complete connection process: get controller ID and login"""
        if not self.get_controller_id():
            self.logger.error("Failed to get controller ID.")
            return False
        
        if not self.login():
            self.logger.error("Login failed.")
            return False
        
        self._authenticated = True
        self.logger.info("Successfully connected to Omada Controller")
        return True
    
    def ensure_authenticated(self) -> bool:
        """Ensure we're authenticated, connect if not"""
        if not self._authenticated:
            return self.connect()
        return True
        
    def get_controller_id(self):
        """Get controller ID from the API"""
        try:
            url = urljoin(self.base_url, "/api/info")
            self._debug_print(f"Getting controller ID from: {url}")
            
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            self.controller_id = data['result']['omadacId']
            self._debug_print(f"Controller ID: {self.controller_id}")
            return self.controller_id
            
        except Exception as e:
            self.logger.error(f"Error getting controller ID: {e}")
            return None
    
    def login(self):
        """Login and get authentication token"""
        if not self.controller_id:
            self.logger.error("Controller ID not set. Call get_controller_id() first.")
            return False
            
        try:
            url = urljoin(self.base_url, f"/{self.controller_id}/api/v2/login")
            
            login_data = {
                "username": self.username,
                "password": self.password
            }
            
            headers = {
                "Content-Type": "application/json"
            }
            
            response = self.session.post(url, json=login_data, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            self.token = data['result']['token']
            return True
            
        except Exception as e:
            self.logger.error(f"Error during login: {e}")
            return False
    
    def make_api_call(self, endpoint, method="GET", params=None, data=None, add_token=True):
        """Generic method to make API calls with proper authentication"""
        if not self.ensure_authenticated():
            return None
            
        try:
            url = urljoin(self.base_url, f"/{self.controller_id}/api/v2/{endpoint}")
            
            headers = {
                "Content-Type": "application/json",
                "Csrf-Token": self.token
            }
            
            # Add token to params if requested and not already present
            if add_token:
                if params is None:
                    params = {}
                if "token" not in params:
                    params["token"] = self.token
            
            self._debug_print(f"API Call - Method: {method}, URL: {url}")
            self._debug_print(f"API Call - Params: {params}")
            
            if method.upper() == "GET":
                response = self.session.get(url, params=params, headers=headers)
            elif method.upper() == "POST":
                response = self.session.post(url, params=params, json=data, headers=headers)
            elif method.upper() == "PUT":
                response = self.session.put(url, params=params, json=data, headers=headers)
            elif method.upper() == "PATCH":
                response = self.session.patch(url, params=params, json=data, headers=headers)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, params=params, headers=headers)
            else:
                self.logger.error(f"Unsupported HTTP method: {method}")
                return None
            
            response.raise_for_status()
            result = response.json()
            
            if result.get('errorCode') != 0:
                self.logger.error(f"API Error: {result.get('msg', 'Unknown error')}")
                return None
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error making API call to {endpoint}: {e}")
            return None

    def get_sites(self, force_refresh=False):
        """Get list of sites with proper pagination"""
        if self.sites and not force_refresh:
            return self.sites
            
        params = {
            "currentPage": 1,
            "currentPageSize": 100
        }
        
        result = self.make_api_call("sites", params=params)
        if result:
            self.sites = result['result']['data']
            # Set the first site as current if no site is selected
            if not self.current_site_key and self.sites:
                self.current_site_key = self.sites[0]['id']
            
            return self.sites
        return None
    
    def set_current_site(self, site_key_or_name):
        """Set the current site by key or name"""
        if not self.sites:
            self.get_sites()
            
        # Try to find by key first, then by name
        for site in self.sites:
            if site['id'] == site_key_or_name or site['name'] == site_key_or_name:
                self.current_site_key = site['id']
                return True
        
        self.logger.warning(f"Site '{site_key_or_name}' not found.")
        return False
    
    def get_current_site(self):
        """Get current site info"""
        if not self.current_site_key:
            return None
            
        for site in self.sites:
            if site['id'] == self.current_site_key:
                return site
        return None

    # Simplified API methods with better return values
    def get_dashboard(self, site_key=None) -> Optional[Dict]:
        """Get dashboard snapshot for a site"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return None
            
        result = self.make_api_call(f"sites/{site_key}/dashboard/overviewDiagram")
        
        return result['result'] if result else None
    
    def get_devices_list(self, site_key=None) -> List[Dict]:
        """Get list of devices for a site"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        params = {
            "currentPage": 1,
            "currentPageSize": 1000
        }
        
        result = self.make_api_call(f"sites/{site_key}/devices", params=params)
        return result['result'] if result else []
    
    def get_clients_list(self, site_key=None, active_only=True) -> List[Dict]:
        """Get list of clients for a site"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        params = {
            "currentPage": 1,
            "currentPageSize": 1000
        }
        
        if active_only:
            params["filters.active"] = "true"
        
        result = self.make_api_call(f"sites/{site_key}/clients", params=params)
        return result['result']['data'] if result and 'result' in result else []
    
    def get_vpn_tunnels(self, site_key=None, server_type=None) -> List[Dict]:
        """Get VPN tunnel statistics
        
        Args:
            site_key: Site key (uses current site if None)
            server_type: 0 for server tunnels, 1 for client tunnels, None for both
        """
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
        
        all_tunnels = []
        
        # If server_type is specified, only get that type
        if server_type is not None:
            params = {
                "currentPage": 1,
                "currentPageSize": 100,
                "filters.server": server_type
            }
            
            result = self.make_api_call(f"sites/{site_key}/setting/vpn/stats/tunnel", params=params)
            return result['result']['data'] if result and 'result' in result else []
        
        # Get both server (0) and client (1) tunnels
        for tunnel_type in [0, 1]:
            params = {
                "currentPage": 1,
                "currentPageSize": 100,
                "filters.server": tunnel_type
            }
            
            result = self.make_api_call(f"sites/{site_key}/setting/vpn/stats/tunnel", params=params)
            if result and 'result' in result and 'data' in result['result']:
                tunnels = result['result']['data']
                # Add tunnel type info for debugging
                for tunnel in tunnels:
                    tunnel['_tunnel_type'] = 'server' if tunnel_type == 0 else 'client'
                all_tunnels.extend(tunnels)
        
        return all_tunnels
    
    def get_vpn_configs(self, site_key=None) -> List[Dict]:
        """Get VPN configurations"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        result = self.make_api_call(f"sites/{site_key}/setting/vpns")
        if result and 'result' in result:
            vpns_data = result['result']
            return vpns_data if isinstance(vpns_data, list) else vpns_data.get('data', [])
        return []
    
    def toggle_vpn(self, vpn_name: str, enabled: bool, site_key=None) -> bool:
        """Enable or disable a VPN by name"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return False
        
        vpns = self.get_vpn_configs(site_key)
        vpn_config = None
        
        for vpn in vpns:
            if vpn.get('name') == vpn_name:
                vpn_config = vpn
                break
        
        if not vpn_config:
            self.vpn_logger.error(f"VPN '{vpn_name}' not found")
            return False
        
        # Update the VPN configuration with new status
        updated_config = vpn_config.copy()
        updated_config['status'] = enabled  # Use 'status' instead of 'enable'
        
        result = self.make_api_call(f"sites/{site_key}/setting/vpns/{vpn_config['id']}", 
                                  method="PATCH", data=updated_config)
        
        if result:
            # Verify the change by getting fresh config
            new_status = self.get_vpn_status(vpn_name, site_key)
            return new_status == enabled
        else:
            self.vpn_logger.error("API call failed")
            return False
    
    def get_alerts_list(self, site_key=None, limit=100) -> List[Dict]:
        """Get recent alerts"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        params = {
            "currentPage": 1,
            "currentPageSize": limit
        }
        
        result = self.make_api_call(f"sites/{site_key}/alerts", params=params)
        return result['result']['data'] if result and 'result' in result else []

    # Utility methods for easy access to common info
    def get_network_summary(self, site_key=None) -> Dict:
        """Get a summary of network status"""
        dashboard = self.get_dashboard(site_key)
        if not dashboard:
            return {}
            
        return {
            'Total_Gateway_Num': dashboard.get('totalGatewayNum', 0),
            'Total_Switch_Num': dashboard.get('totalSwitchNum', 0),
            'Total_Ap_Num': dashboard.get('totalApNum', 0),
            'Total_Clients': dashboard.get('totalClientNum', 0),
            'wired_clients': dashboard.get('wiredClientNum', 0),
            'wireless_clients': dashboard.get('wirelessClientNum', 0),
            'guest_clients': dashboard.get('guestNum', 0),
            'wan_Port_Info': dashboard.get('wanPortInfos')
        }
    
    def find_device_by_name(self, device_name: str, site_key=None) -> Optional[Dict]:
        """Find a device by name"""
        devices = self.get_devices_list(site_key)
        for device in devices:
            if device.get('name', '').lower() == device_name.lower():
                return device
        return None
    
    def find_client_by_name(self, client_name: str, site_key=None, active_only=True) -> Optional[Dict]:
        """Find a client by exact name match"""
        clients = self.get_clients_list(site_key, active_only)
        for client in clients:
            if client.get('name', '').lower() == client_name.lower():
                return client
        return None
    
    def search_clients(self, search_term: str, site_key=None, active_only=True, 
                      search_type='fuzzy', limit=10) -> List[Dict]:
        """Advanced client search with multiple search types
        
        Args:
            search_term: Term to search for
            site_key: Site key (uses current site if None)
            active_only: Search only active clients
            search_type: 'exact', 'partial', 'fuzzy', 'mac', 'ip'
            limit: Maximum number of results
        """
        clients = self.get_clients_list(site_key, active_only)
        results = []
        search_term_lower = search_term.lower()
        
        for client in clients:
            name = client.get('name', '').lower()
            mac = client.get('mac', '').lower()
            ip = client.get('ip', '')
            
            match_score = 0
            match_reason = ""
            
            if search_type == 'exact':
                if name == search_term_lower:
                    match_score = 100
                    match_reason = "exact name match"
            
            elif search_type == 'partial':
                if search_term_lower in name:
                    match_score = 80 if name.startswith(search_term_lower) else 60
                    match_reason = "partial name match"
            
            elif search_type == 'mac':
                # Remove common MAC separators for comparison
                clean_search = search_term.replace(':', '').replace('-', '').lower()
                clean_mac = mac.replace(':', '').replace('-', '')
                if clean_search in clean_mac:
                    match_score = 90
                    match_reason = "MAC address match"
            
            elif search_type == 'ip':
                if search_term in ip:
                    match_score = 90
                    match_reason = "IP address match"
            
            elif search_type == 'fuzzy':
                # Fuzzy matching - check multiple criteria
                if name == search_term_lower:
                    match_score = 100
                    match_reason = "exact name match"
                elif search_term_lower in name:
                    match_score = 80 if name.startswith(search_term_lower) else 60
                    match_reason = "partial name match"
                elif self._fuzzy_match(search_term_lower, name):
                    match_score = 40
                    match_reason = "fuzzy name match"
                # Also check MAC and IP in fuzzy mode
                elif search_term.replace(':', '').replace('-', '').lower() in mac.replace(':', '').replace('-', ''):
                    match_score = 70
                    match_reason = "MAC address match"
                elif search_term in ip:
                    match_score = 70
                    match_reason = "IP address match"
            
            if match_score > 0:
                client_result = client.copy()
                client_result['_match_score'] = match_score
                client_result['_match_reason'] = match_reason
                results.append(client_result)
        
        # Sort by match score (highest first) and limit results
        results.sort(key=lambda x: x['_match_score'], reverse=True)
        return results[:limit]
    
    def search_devices(self, search_term: str, site_key=None, search_type='fuzzy', limit=10) -> List[Dict]:
        """Advanced device search with multiple search types"""
        devices = self.get_devices_list(site_key)
        results = []
        search_term_lower = search_term.lower()
        
        for device in devices:
            name = device.get('name', '').lower()
            mac = device.get('mac', '').lower()
            model = device.get('model', '').lower()
            
            match_score = 0
            match_reason = ""
            
            if search_type == 'exact':
                if name == search_term_lower:
                    match_score = 100
                    match_reason = "exact name match"
            
            elif search_type == 'partial':
                if search_term_lower in name:
                    match_score = 80 if name.startswith(search_term_lower) else 60
                    match_reason = "partial name match"
            
            elif search_type == 'mac':
                clean_search = search_term.replace(':', '').replace('-', '').lower()
                clean_mac = mac.replace(':', '').replace('-', '')
                if clean_search in clean_mac:
                    match_score = 90
                    match_reason = "MAC address match"
            
            elif search_type == 'model':
                if search_term_lower in model:
                    match_score = 70
                    match_reason = "model match"
            
            elif search_type == 'fuzzy':
                if name == search_term_lower:
                    match_score = 100
                    match_reason = "exact name match"
                elif search_term_lower in name:
                    match_score = 80 if name.startswith(search_term_lower) else 60
                    match_reason = "partial name match"
                elif self._fuzzy_match(search_term_lower, name):
                    match_score = 40
                    match_reason = "fuzzy name match"
                elif search_term_lower in model:
                    match_score = 50
                    match_reason = "model match"
                elif search_term.replace(':', '').replace('-', '').lower() in mac.replace(':', '').replace('-', ''):
                    match_score = 70
                    match_reason = "MAC address match"
            
            if match_score > 0:
                device_result = device.copy()
                device_result['_match_score'] = match_score
                device_result['_match_reason'] = match_reason
                results.append(device_result)
        
        results.sort(key=lambda x: x['_match_score'], reverse=True)
        return results[:limit]
    
    def _fuzzy_match(self, search_term: str, target: str, threshold=0.6) -> bool:
        """Simple fuzzy matching based on character overlap"""
        if not search_term or not target:
            return False
        
        # Calculate character overlap ratio
        search_chars = set(search_term.lower())
        target_chars = set(target.lower())
        
        if len(search_chars) == 0:
            return False
        
        overlap = len(search_chars.intersection(target_chars))
        ratio = overlap / len(search_chars)
        
        return ratio >= threshold
    
    def get_vpn_status(self, vpn_name: str, site_key=None) -> Optional[bool]:
        """Get VPN enabled status by name"""
        vpns = self.get_vpn_configs(site_key)
        for vpn in vpns:
            if vpn.get('name') == vpn_name:
                return vpn.get('status', False)  # Use 'status' instead of 'enable'
        return None

    # WireGuard Methods
    def get_wireguard_peers(self, site_key=None, page=1, page_size=10) -> List[Dict]:
        """Get WireGuard peers list"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        params = {
            "currentPage": page,
            "currentPageSize": page_size
        }
        
        result = self.make_api_call(f"sites/{site_key}/setting/wireguard/peer", params=params)
        return result['result']['data'] if result and 'result' in result else []
    
    def get_wireguard_servers(self, site_key=None, page=1, page_size=10) -> List[Dict]:
        """Get WireGuard servers list"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        params = {
            "currentPage": page,
            "currentPageSize": page_size
        }
        
        result = self.make_api_call(f"sites/{site_key}/setting/wireguard", params=params)
        return result['result']['data'] if result and 'result' in result else []
    
    def get_wireguard_insights(self, site_key=None, page=1, page_size=10, server_filter=0) -> List[Dict]:
        """Get WireGuard connection insights
        
        Args:
            site_key: Site key (uses current site if None)
            page: Page number for pagination
            page_size: Number of items per page
            server_filter: Server filter (0 for all, specific server ID for filtering)
        """
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        params = {
            "currentPage": page,
            "currentPageSize": page_size,
            "filters.server": server_filter
        }
        
        result = self.make_api_call(f"sites/{site_key}/insight/wireguard", params=params)
        return result['result']['data'] if result and 'result' in result else []
    
    def create_wireguard_peer(self, peer_config: Dict, site_key=None) -> bool:
        """Create a new WireGuard peer
        
        Args:
            peer_config: Dictionary containing peer configuration
            site_key: Site key (uses current site if None)
        """
        site_key = site_key or self.current_site_key
        if not site_key:
            return False
            
        result = self.make_api_call(f"sites/{site_key}/setting/wireguard/peer", 
                                  method="POST", data=peer_config)
        return result is not None
    
    def update_wireguard_peer(self, peer_id: str, peer_config: Dict, site_key=None) -> bool:
        """Update an existing WireGuard peer
        
        Args:
            peer_id: ID of the peer to update
            peer_config: Dictionary containing updated peer configuration
            site_key: Site key (uses current site if None)
        """
        site_key = site_key or self.current_site_key
        if not site_key:
            return False
        
        self.logger.debug(f"Updating WireGuard peer {peer_id} with config: {peer_config}")
        
        # Use PUT method with the peer ID in the URL as shown in your example
        result = self.make_api_call(f"sites/{site_key}/setting/wireguard/peer/{peer_id}", 
                                  method="PUT", data=peer_config)
        return result is not None
    
    def delete_wireguard_peer(self, peer_id: str, site_key=None) -> bool:
        """Delete a WireGuard peer
        
        Args:
            peer_id: ID of the peer to delete
            site_key: Site key (uses current site if None)
        """
        site_key = site_key or self.current_site_key
        if not site_key:
            return False
            
        result = self.make_api_call(f"sites/{site_key}/setting/wireguard/peer/{peer_id}", 
                                  method="DELETE")
        return result is not None
    
    def get_wireguard_peer_by_name(self, peer_name: str, site_key=None) -> Optional[Dict]:
        """Find a WireGuard peer by name"""
        peers = self.get_wireguard_peers(site_key)
        for peer in peers:
            if peer.get('name', '').lower() == peer_name.lower():
                return peer
        return None
    
    def toggle_wireguard_peer(self, peer_name: str, enabled: bool, site_key=None) -> bool:
        """Enable or disable a WireGuard peer by name
        
        Args:
            peer_name: Name of the peer to toggle
            enabled: True to enable, False to disable
            site_key: Site key (uses current site if None)
        """
        peer = self.get_wireguard_peer_by_name(peer_name, site_key)
        if not peer:
            self.logger.error(f"WireGuard peer '{peer_name}' not found")
            return False
        
        updated_config = peer.copy()
        updated_config['status'] = enabled  # Use 'status' instead of 'enable'
        
        return self.update_wireguard_peer(peer['id'], updated_config, site_key)

def create_controller(base_url: str, username: str, password: str, debug: bool = False) -> OmadaController:
    """Factory function to create and connect to Omada Controller"""
    controller = OmadaController(base_url, username, password, debug)
    if controller.connect():
        controller.get_sites()  # Load sites immediately
        return controller
    else:
        raise ConnectionError("Failed to connect to Omada Controller")

def get_config():
    """Get configuration from environment variables or defaults"""
    return {
        'url': os.getenv('OMADA_URL'),
        'username': os.getenv('OMADA_USERNAME'),
        'password': os.getenv('OMADA_PASSWORD')
    }

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
        logger.info(f"No clients found matching '{args.name}' using {search_type} search")
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
        logger.info(f"🔍 Found {len(results)} clients matching '{args.name}':")
        for i, client in enumerate(results, 1):
            logger.info(f"  {i}. {client.get('name', 'Unknown')}")
            logger.info(f"     MAC: {client.get('mac', 'Unknown')} | IP: {client.get('ip', 'No IP')}")
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
        logger.info(f"    Public Key: {peer.get('publicKey', 'N/A')[:20]}...")
        
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
        
        # Show MTU
        mtu = server.get('mtu')
        if mtu:
            logger.info(f"    MTU: {mtu}")
        
        logger.info("")  # Empty line between servers

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
        status = "enabled" if peer.get('enable', False) else "disabled"
        logger.info(f"WireGuard peer '{args.name}' is {status}")
        logger.info(f"  Public Key: {peer.get('publicKey', 'N/A')}")
        logger.info(f"  Allowed IPs: {peer.get('allowedIps', 'N/A')}")
        if peer.get('endpoint'):
            logger.info(f"  Endpoint: {peer.get('endpoint')}")

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

# Custom Actions System
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
        # Client VPNs typically have purpose=1 (client-to-site) and mode indicators
        client_vpns = []
        server_vpns = []
        
        for vpn in enabled_vpns:
            vpn_name = vpn.get('name', 'Unknown')
            
            
            # Correct VPN type detection logic based on actual data:
            # 
            # Client VPNs have:
            # - clientVpnType1: 1 (indicates it's a client)
            # - remoteIp: <actual_ip> (server they connect to)
            # - vpnConfiguration: {...} (client config file)
            #
            # Server VPNs have:
            # - clientVpnType1: 0 (indicates it's NOT a client, so it's a server)
            # - remoteIp: not_present (they don't connect out, they accept connections)
            # - vpnConfiguration: not_present (no client config needed)
            
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
    action_name = args.action_name
    
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
  %(prog)s find device --search-type mac "aa:bb:cc"  # Find device by MAC
  %(prog)s find client "Galaxy"            # Find client by name (fuzzy search)
  %(prog)s find client --search-type ip "192.168"    # Find client by IP
  %(prog)s find client --all "Phone"       # Search all clients (not just active)
  %(prog)s action vpn-health-check         # Check VPN health and restart if needed
  %(prog)s action network-status           # Generate network status report
  %(prog)s action vpn-bulk-restart --force # Restart all enabled VPNs
        """
    )
    
    parser.add_argument('--url', help='Omada Controller URL')
    parser.add_argument('--username', help='Username')
    parser.add_argument('--password', help='Password')
    parser.add_argument('--site', help='Site ID or name')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
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
    action_parser = subparsers.add_parser('action', help='Execute custom actions')
    action_parser.add_argument('action_name', choices=list(CUSTOM_ACTIONS.keys()), 
                              help='Custom action to execute')
    action_parser.add_argument('--force', action='store_true', 
                              help='Skip confirmation prompts')
    
    return parser

def main():
    load_dotenv()
    parser = create_parser()
    args = parser.parse_args()
    
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
    
    try:
        # Create controller connection
        controller = create_controller(url, username, password, args.debug)
        
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
        elif args.command == 'action':
            cmd_custom_action(controller, args)
        
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