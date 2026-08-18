"""Omada internal API v2 client (cookie/CSRF-token web API)."""
import json
import logging
from urllib.parse import urljoin
from typing import Optional, Dict, List, Any

import requests
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

    def _request(self, endpoint: str, method: str = "GET", params: Dict = None, data: Dict = None, 
                 add_token: bool = True, retry_auth: bool = True) -> Optional[Dict]:
        """
        Centralized request method that handles all API calls with automatic authentication
        
        Args:
            endpoint: API endpoint (without base URL and controller ID)
            method: HTTP method
            params: Query parameters
            data: Request body data
            add_token: Whether to add authentication token
            retry_auth: Whether to retry authentication on failure
        """
        # Ensure we have controller ID and are authenticated
        if not self._ensure_ready():
            return None
        
        try:
            # Build URL
            url = urljoin(self.base_url, f"/{self.controller_id}/api/v2/{endpoint}")
            
            # Prepare headers
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Csrf-Token"] = self.token
            
            # Add token to params if requested
            if add_token and self.token:
                if params is None:
                    params = {}
                if "token" not in params:
                    params["token"] = self.token
            
            self._debug_print(f"Request - Method: {method}, URL: {url}")
            self._debug_print(f"Request - Params: {params}")
            
            # Make the request
            response = self._make_http_request(url, method, headers, params, data)
            
            if response is None:
                return None
            
            # Parse response
            try:
                result = response.json()
            except json.JSONDecodeError:
                self.logger.error("Invalid JSON response")
                return None
            
            # Check for API errors
            if result.get('errorCode') != 0:
                error_msg = result.get('msg', 'Unknown error')
                
                # Handle authentication errors with retry
                if retry_auth and ('login' in error_msg.lower() or 'auth' in error_msg.lower() or result.get('errorCode') == -1010):
                    self.logger.warning(f"Authentication error detected: {error_msg}")
                    if self._reauthenticate():
                        self.logger.info("Reauthentication successful, retrying request...")
                        return self._request(endpoint, method, params, data, add_token, retry_auth=False)
                
                self.logger.error(f"API Error: {error_msg}")
                return None
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error making request to {endpoint}: {e}")
            return None

    def _make_http_request(self, url: str, method: str, headers: Dict, params: Dict, data: Dict):
        """Make the actual HTTP request"""
        try:
            if method.upper() == "GET":
                return self.session.get(url, params=params, headers=headers)
            elif method.upper() == "POST":
                return self.session.post(url, params=params, json=data, headers=headers)
            elif method.upper() == "PUT":
                return self.session.put(url, params=params, json=data, headers=headers)
            elif method.upper() == "PATCH":
                return self.session.patch(url, params=params, json=data, headers=headers)
            elif method.upper() == "DELETE":
                return self.session.delete(url, params=params, headers=headers)
            else:
                self.logger.error(f"Unsupported HTTP method: {method}")
                return None
        except requests.RequestException as e:
            self.logger.error(f"HTTP request failed: {e}")
            return None

    def _ensure_ready(self) -> bool:
        """Ensure controller ID is available and authentication is ready"""
        # Get controller ID if not available
        if not self.controller_id:
            if not self._get_controller_id():
                return False
        
        # Authenticate if not already authenticated
        if not self._authenticated:
            if not self._authenticate():
                return False
        
        return True

    def _get_controller_id(self) -> bool:
        """Get controller ID from the API"""
        try:
            url = urljoin(self.base_url, "/api/info")
            self._debug_print(f"Getting controller ID from: {url}")
            
            response = self.session.get(url)
            response.raise_for_status()
            
            data = response.json()
            self.controller_id = data['result']['omadacId']
            self._debug_print(f"Controller ID: {self.controller_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error getting controller ID: {e}")
            return False

    def _authenticate(self) -> bool:
        """Perform authentication and get token"""
        if not self.controller_id:
            self.logger.error("Controller ID not available for authentication")
            return False
            
        try:
            url = urljoin(self.base_url, f"/{self.controller_id}/api/v2/login")
            
            login_data = {
                "username": self.username,
                "password": self.password
            }
            
            headers = {"Content-Type": "application/json"}
            
            response = self.session.post(url, json=login_data, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            if data.get('errorCode') != 0:
                self.logger.error(f"Authentication failed: {data.get('msg', 'Unknown error')}")
                return False
            
            self.token = data['result']['token']
            self._authenticated = True
            self.logger.info("Authentication successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Error during authentication: {e}")
            return False

    def _reauthenticate(self) -> bool:
        """Reauthenticate after token expiry"""
        self.logger.info("Attempting reauthentication...")
        self._authenticated = False
        self.token = None
        return self._authenticate()

    def get_sites(self, force_refresh=False):
        """Get list of sites with proper pagination"""
        if self.sites and not force_refresh:
            return self.sites
            
        params = {
            "currentPage": 1,
            "currentPageSize": 100
        }
        
        result = self._request("sites", params=params)
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

    # Simplified API methods using centralized request handling
    def get_dashboard(self, site_key=None) -> Optional[Dict]:
        """Get dashboard snapshot for a site"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return None
            
        result = self._request(f"sites/{site_key}/dashboard/overviewDiagram")
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
        
        result = self._request(f"sites/{site_key}/devices", params=params)
        return result['result'] if result else []
    
    def get_clients_list(self, site_key=None, active_only=True) -> List[Dict]:
        """Get list of clients for a site"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        params = {
            "currentPage": 1,
            "currentPageSize": 1000,
            # The clients endpoint requires filters.active; omitting it returns
            # a "General error". Send it explicitly for both active and all.
            "filters.active": "true" if active_only else "false",
        }

        result = self._request(f"sites/{site_key}/clients", params=params)
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
            
            result = self._request(f"sites/{site_key}/setting/vpn/stats/tunnel", params=params)
            return result['result']['data'] if result and 'result' in result else []
        
        # Get both server (0) and client (1) tunnels
        for tunnel_type in [0, 1]:
            params = {
                "currentPage": 1,
                "currentPageSize": 100,
                "filters.server": tunnel_type
            }
            
            result = self._request(f"sites/{site_key}/setting/vpn/stats/tunnel", params=params)
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
            
        result = self._request(f"sites/{site_key}/setting/vpns")
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
        updated_config['status'] = enabled
        
        result = self._request(f"sites/{site_key}/setting/vpns/{vpn_config['id']}", 
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
        
        result = self._request(f"sites/{site_key}/alerts", params=params)
        return result['result']['data'] if result and 'result' in result else []

    # Networking config methods (VLANs, SSIDs, ACLs, groups)
    def get_networks(self, site_key=None) -> List[Dict]:
        """Get wired LAN networks (VLANs) for a site"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []

        params = {"currentPage": 1, "currentPageSize": 100}
        result = self._request(f"sites/{site_key}/setting/lan/networks", params=params)
        return result['result']['data'] if result and 'result' in result else []

    def get_wlan_groups(self, site_key=None) -> List[Dict]:
        """Get WLAN groups for a site"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []

        result = self._request(f"sites/{site_key}/setting/wlans")
        return result['result']['data'] if result and 'result' in result else []

    def get_ssids(self, wlan_id=None, site_key=None) -> List[Dict]:
        """Get SSIDs for a WLAN group (defaults to the primary group)"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []

        if not wlan_id:
            groups = self.get_wlan_groups(site_key)
            if not groups:
                return []
            primary = next((g for g in groups if g.get('primary')), groups[0])
            wlan_id = primary['id']

        params = {"currentPage": 1, "currentPageSize": 100}
        result = self._request(f"sites/{site_key}/setting/wlans/{wlan_id}/ssids", params=params)
        return result['result']['data'] if result and 'result' in result else []

    def get_acls(self, acl_type="gateway", site_key=None) -> List[Dict]:
        """Get ACL rules for a site. acl_type: gateway | switch | eap"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []

        type_map = {"gateway": 0, "switch": 1, "eap": 2}
        params = {
            "currentPage": 1,
            "currentPageSize": 100,
            "type": type_map.get(acl_type, 0),
        }
        result = self._request(f"sites/{site_key}/setting/firewall/acls", params=params)
        return result['result']['data'] if result and 'result' in result else []

    def get_groups(self, site_key=None) -> List[Dict]:
        """Get IP / domain groups (profiles) for a site"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []

        result = self._request(f"sites/{site_key}/setting/profiles/groups")
        return result['result']['data'] if result and 'result' in result else []

    def get_group_by_name(self, name, site_key=None) -> Optional[Dict]:
        """Find an IP/domain group by name"""
        for group in self.get_groups(site_key):
            if group.get('name') == name:
                return group
        return None

    def get_acl_by_id(self, acl_id, acl_type="gateway", site_key=None) -> Optional[Dict]:
        """Find an ACL rule by id"""
        for acl in self.get_acls(acl_type, site_key):
            if acl.get('id') == acl_id:
                return acl
        return None

    def get_acl_by_name(self, name, acl_type="gateway", site_key=None) -> Optional[Dict]:
        """Find an ACL rule by name"""
        for acl in self.get_acls(acl_type, site_key):
            if acl.get('name') == name:
                return acl
        return None

    # --- Write operations (networking config) ---
    def update_group(self, group_id, group_obj, site_key=None) -> Optional[Dict]:
        """Update an IP/domain group.

        Verb differs by controller build: v6.2 uses PATCH on `.../groups/{type}/{id}`;
        older builds use PUT on `.../groups/{id}`. Try PATCH first, fall back to PUT.
        """
        site_key = site_key or self.current_site_key
        if not site_key:
            return None
        gtype = group_obj.get('type', 0)
        result = self._request(f"sites/{site_key}/setting/profiles/groups/{gtype}/{group_id}",
                               method="PATCH", data=group_obj)
        if result is None:
            result = self._request(f"sites/{site_key}/setting/profiles/groups/{group_id}",
                                   method="PUT", data=group_obj)
        return result

    def create_acl(self, acl_obj, site_key=None) -> Optional[Dict]:
        """Create a firewall ACL rule (POST)."""
        site_key = site_key or self.current_site_key
        if not site_key:
            return None
        return self._request(f"sites/{site_key}/setting/firewall/acls",
                             method="POST", data=acl_obj,
                             params={"type": acl_obj.get('type', 0)})

    def update_acl(self, acl_id, acl_obj, site_key=None) -> Optional[Dict]:
        """Update a firewall ACL rule (PUT; PATCH is rejected on v6)."""
        site_key = site_key or self.current_site_key
        if not site_key:
            return None
        return self._request(f"sites/{site_key}/setting/firewall/acls/{acl_id}",
                             method="PUT", data=acl_obj)

    def get_client(self, mac, site_key=None) -> Optional[Dict]:
        """Get a single client by MAC (dash-separated)."""
        site_key = site_key or self.current_site_key
        if not site_key:
            return None
        result = self._request(f"sites/{site_key}/clients/{mac}")
        return result['result'] if result and 'result' in result else None

    def update_client(self, mac, body, site_key=None) -> Optional[Dict]:
        """Update a client (PATCH), e.g. to set a fixed-IP reservation."""
        site_key = site_key or self.current_site_key
        if not site_key:
            return None
        return self._request(f"sites/{site_key}/clients/{mac}", method="PATCH", data=body)

    def get_mdns(self, site_key=None) -> Optional[Dict]:
        """Get the mDNS reflector state (global toggle)."""
        site_key = site_key or self.current_site_key
        if not site_key:
            return None
        result = self._request(f"sites/{site_key}/setting/mdns")
        return result['result'] if result and 'result' in result else None

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
                return vpn.get('status', False)
        return None

    # WireGuard Methods using centralized request handling
    def get_wireguard_peers(self, site_key=None, page=1, page_size=10) -> List[Dict]:
        """Get WireGuard peers list"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        params = {
            "currentPage": page,
            "currentPageSize": page_size
        }
        
        result = self._request(f"sites/{site_key}/setting/wireguard/peer", params=params)
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
        
        result = self._request(f"sites/{site_key}/setting/wireguard", params=params)
        return result['result']['data'] if result and 'result' in result else []
    
    def get_wireguard_insights(self, site_key=None, page=1, page_size=10, server_filter=0) -> List[Dict]:
        """Get WireGuard connection insights"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return []
            
        params = {
            "currentPage": page,
            "currentPageSize": page_size,
            "filters.server": server_filter
        }
        
        result = self._request(f"sites/{site_key}/insight/wireguard", params=params)
        return result['result']['data'] if result and 'result' in result else []
    
    def create_wireguard_peer(self, peer_config: Dict, site_key=None) -> bool:
        """Create a new WireGuard peer"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return False
            
        result = self._request(f"sites/{site_key}/setting/wireguard/peer", 
                              method="POST", data=peer_config)
        return result is not None
    
    def update_wireguard_peer(self, peer_id: str, peer_config: Dict, site_key=None) -> bool:
        """Update an existing WireGuard peer"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return False
        
        self.logger.debug(f"Updating WireGuard peer {peer_id} with config: {peer_config}")
        
        result = self._request(f"sites/{site_key}/setting/wireguard/peer/{peer_id}", 
                              method="PUT", data=peer_config)
        return result is not None
    
    def delete_wireguard_peer(self, peer_id: str, site_key=None) -> bool:
        """Delete a WireGuard peer"""
        site_key = site_key or self.current_site_key
        if not site_key:
            return False
            
        result = self._request(f"sites/{site_key}/setting/wireguard/peer/{peer_id}", 
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
        """Enable or disable a WireGuard peer by name"""
        peer = self.get_wireguard_peer_by_name(peer_name, site_key)
        if not peer:
            self.logger.error(f"WireGuard peer '{peer_name}' not found")
            return False
        
        updated_config = peer.copy()
        updated_config['status'] = enabled
        
        return self.update_wireguard_peer(peer['id'], updated_config, site_key)

def create_controller(base_url: str, username: str, password: str, debug: bool = False) -> OmadaController:
    """Factory function to create Omada Controller with lazy authentication"""
    controller = OmadaController(base_url, username, password, debug)
    return controller

