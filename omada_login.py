#!/usr/bin/env python3
"""
Omada VPN Client Manager - Optimized Version

A Python script for managing TP-Link Omada VPN clients via the OpenAPI.
Supports enable, disable, and restart operations with improved error handling,
logging, and configuration management.
"""

import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

import requests
import urllib3
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry


class VPNAction(Enum):
    """Supported VPN actions"""
    ENABLE = "enable"
    DISABLE = "disable" 
    RESTART = "restart"
    TOKEN_ONLY = "token_only"


@dataclass
class OmadaConfig:
    """Configuration container for Omada connection parameters"""
    base_url: str
    client_id: str
    client_secret: str
    omadac_id: str
    username: str
    password: str
    vpn_name: str
    vpn_action: VPNAction = VPNAction.DISABLE
    verify_ssl: bool = False
    timeout: int = 30
    retry_attempts: int = 3
    
    @classmethod
    def from_env(cls) -> 'OmadaConfig':
        """Create configuration from environment variables"""
        load_dotenv()
        
        # Get required variables
        required_vars = {
            'base_url': os.getenv('OMADA_URL'),
            'client_id': os.getenv('OMADA_CLIENT_ID'), 
            'client_secret': os.getenv('OMADA_CLIENT_SECRET'),
            'omadac_id': os.getenv('OMADA_OMADAC_ID'),
            'username': os.getenv('OMADA_USERNAME'),
            'password': os.getenv('OMADA_PASSWORD'),
            'vpn_name': os.getenv('OMADA_VPN_NAME')
        }
        
        # Check for missing variables
        missing = [key for key, value in required_vars.items() if not value]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing.upper())}")
        
        # Get optional variables
        vpn_action_str = os.getenv('OMADA_VPN_ACTION', 'disable').lower()
        
        try:
            vpn_action = VPNAction(vpn_action_str)
        except ValueError:
            valid_actions = [action.value for action in VPNAction]
            raise ValueError(f"Invalid VPN action '{vpn_action_str}'. Must be one of: {valid_actions}")
        
        # For token_only mode, vpn_name is not required
        if vpn_action == VPNAction.TOKEN_ONLY and not required_vars['vpn_name']:
            required_vars['vpn_name'] = "not_required_for_token_only"
        
        return cls(
            **required_vars,
            vpn_action=vpn_action,
            verify_ssl=os.getenv('OMADA_VERIFY_SSL', 'false').lower() == 'true',
            timeout=int(os.getenv('OMADA_TIMEOUT', '30')),
            retry_attempts=int(os.getenv('OMADA_RETRY_ATTEMPTS', '3'))
        )


class OmadaAPIError(Exception):
    """Custom exception for Omada API errors"""
    def __init__(self, message: str, error_code: int = None):
        self.error_code = error_code
        super().__init__(message)


class OmadaVPNManager:
    """Main class for managing Omada VPN clients"""
    
    def __init__(self, config: OmadaConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.session = self._create_session()
        self.access_token: Optional[str] = None
        
        # Suppress SSL warnings if SSL verification is disabled
        if not config.verify_ssl:
            urllib3.disable_warnings(InsecureRequestWarning)
    
    def _setup_logging(self) -> logging.Logger:
        """Configure logging with proper formatting"""
        logger = logging.getLogger('omada_vpn_manager')
        
        # Get logging configuration from environment
        log_level = getattr(logging, "INFO", logging.INFO)
        log_to_file = os.getenv('OMADA_LOG_TO_FILE', 'false').lower() == 'true'
        
        logger.setLevel(log_level)
        
        if not logger.handlers:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            if log_to_file:
                # Create logs directory if it doesn't exist
                os.makedirs('logs', exist_ok=True)
                
                # Create log filename with timestamp
                from datetime import datetime
                log_filename = f"logs/omada_vpn_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                
                # Add file handler
                file_handler = logging.FileHandler(log_filename)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
                
                # Also add console handler for important messages
                console_handler = logging.StreamHandler()
                console_handler.setLevel(logging.WARNING)  # Only warnings and errors to console
                console_handler.setFormatter(formatter)
                logger.addHandler(console_handler)
            else:
                # Console only
                handler = logging.StreamHandler()
                handler.setFormatter(formatter)
                logger.addHandler(handler)
        
        return logger
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy and timeouts"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.retry_attempts,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with common configuration"""
        kwargs.setdefault('timeout', self.config.timeout)
        kwargs.setdefault('verify', self.config.verify_ssl)
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {method} {url} - {str(e)}")
            raise
    
    def _handle_api_response(self, response: requests.Response, context: str = "") -> Dict:
        """Handle API response and check for errors"""
        try:
            result = response.json()
        except json.JSONDecodeError as e:
            raise OmadaAPIError(f"Invalid JSON response{' for ' + context if context else ''}: {str(e)}")
        
        error_code = result.get("errorCode", -1)
        if error_code != 0:
            message = result.get("msg", "Unknown API error")
            raise OmadaAPIError(f"API error{' for ' + context if context else ''}: {message}", error_code)
        
        return result
    
    def authenticate(self) -> str:
        """Authenticate with Omada controller and return access token"""
        self.logger.info("Starting authentication process...")
        
        try:
            # Step 1: Login to get CSRF token and session ID
            self.logger.info("Step 1: Obtaining CSRF token and session ID...")
            csrf_token, session_id = self._login()
            
            # Step 2: Get authorization code
            self.logger.info("Step 2: Obtaining authorization code...")
            auth_code = self._get_authorization_code(csrf_token, session_id)
            
            # Step 3: Get access token
            self.logger.info("Step 3: Obtaining access token...")
            token_info = self._get_access_token(auth_code)
            
            self.access_token = token_info['accessToken']
            self._save_token_info(token_info)
            
            self.logger.info("Authentication successful!")
            return self.access_token
            
        except Exception as e:
            self.logger.error(f"Authentication failed: {str(e)}")
            raise
    
    def _login(self) -> tuple[str, str]:
        """Login and return CSRF token and session ID"""
        url = f"{self.config.base_url}/openapi/authorize/login"
        params = {
            "client_id": self.config.client_id,
            "omadac_id": self.config.omadac_id
        }
        data = {
            "username": self.config.username,
            "password": self.config.password
        }
        
        response = self._make_request("POST", url, params=params, json=data)
        result = self._handle_api_response(response, "login")
        
        return result["result"]["csrfToken"], result["result"]["sessionId"]
    
    def _get_authorization_code(self, csrf_token: str, session_id: str) -> str:
        """Get authorization code using CSRF token and session ID"""
        url = f"{self.config.base_url}/openapi/authorize/code"
        params = {
            "client_id": self.config.client_id,
            "omadac_id": self.config.omadac_id,
            "response_type": "code"
        }
        headers = {
            "Content-Type": "application/json",
            "Csrf-Token": csrf_token,
            "Cookie": f"TPOMADA_SESSIONID={session_id}"
        }
        
        response = self._make_request("POST", url, params=params, headers=headers)
        result = self._handle_api_response(response, "authorization code")
        
        return result["result"]
    
    def _get_access_token(self, auth_code: str) -> Dict:
        """Exchange authorization code for access token"""
        url = f"{self.config.base_url}/openapi/authorize/token"
        params = {
            "grant_type": "authorization_code",
            "code": auth_code
        }
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret
        }
        
        response = self._make_request("POST", url, params=params, json=data)
        result = self._handle_api_response(response, "access token")
        
        return result["result"]
    
    def _save_token_info(self, token_info: Dict) -> None:
        """Save token information to file for debugging/reference"""
        try:
            token_file = Path("omada_token.json")
            with token_file.open('w') as f:
                json.dump(token_info, f, indent=2)
            self.logger.debug(f"Token info saved to {token_file}")
        except Exception as e:
            self.logger.warning(f"Could not save token info: {str(e)}")
    
    def get_sites(self, page: int = 1, page_size: int = 10) -> List[Dict]:
        """Get list of sites from Omada controller"""
        if not self.access_token:
            raise OmadaAPIError("Not authenticated. Call authenticate() first.")
        
        url = f"{self.config.base_url}/openapi/v1/{self.config.omadac_id}/sites"
        params = {"page": page, "pageSize": page_size}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"AccessToken={self.access_token}"
        }
        
        response = self._make_request("GET", url, params=params, headers=headers)
        result = self._handle_api_response(response, "sites")
        
        return result.get("result", {}).get("data", [])
    
    def get_vpn_clients(self, site_id: str) -> List[Dict]:
        """Get VPN clients for a specific site"""
        if not self.access_token:
            raise OmadaAPIError("Not authenticated. Call authenticate() first.")
        
        url = f"{self.config.base_url}/openapi/v1/{self.config.omadac_id}/sites/{site_id}/vpn/client-to-site-vpn-clients"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"AccessToken={self.access_token}"
        }
        
        response = self._make_request("GET", url, headers=headers)
        result = self._handle_api_response(response, "VPN clients")
        
        clients = result.get("result", {}).get("data", [])
        
        # Log client information
        if clients:
            self.logger.info("VPN Clients found:")
            for client in clients:
                status = "ACTIVE" if client.get("status") else "INACTIVE"
                self.logger.info(f"  - {client.get('name')} ({status})")
        else:
            self.logger.info("No VPN clients found")
        
        return clients
    
    def find_vpn_client(self, site_id: str, vpn_name: str) -> Optional[Dict]:
        """Find a VPN client by name"""
        clients = self.get_vpn_clients(site_id)
        
        for client in clients:
            if client.get("name") == vpn_name:
                return client
        
        return None
    
    def update_vpn_client_status(self, site_id: str, vpn_client: Dict, new_status: bool) -> bool:
        """Update VPN client status"""
        if not self.access_token:
            raise OmadaAPIError("Not authenticated. Call authenticate() first.")
        
        vpn_id = vpn_client.get("id")
        url = f"{self.config.base_url}/openapi/v1/{self.config.omadac_id}/sites/{site_id}/vpn/client-to-site-vpn-clients/{vpn_id}"
        
        # Create payload with all required fields
        payload = {
            "id": vpn_client.get("id", ""),
            "name": vpn_client.get("name", ""),
            "status": new_status,
            "mode": vpn_client.get("mode", 0),
            "remoteSite": vpn_client.get("remoteSite", ""),
            "remoteIp": vpn_client.get("remoteIp", ""),
            "remoteSubnet": vpn_client.get("remoteSubnet", []),
            "networkType": vpn_client.get("networkType", 0),
            "networkList": vpn_client.get("networkList", []),
            "customNetwork": vpn_client.get("customNetwork", []),
            "preSharedKey": vpn_client.get("preSharedKey", ""),
            "wan": vpn_client.get("wan", []),
            "clientVpnType": vpn_client.get("clientVpnType", 0),
            "openVpnTunnelMode": vpn_client.get("openVpnTunnelMode", 0),
            "openVpnMode": vpn_client.get("openVpnMode", 0),
            "serviceType": vpn_client.get("serviceType", 0),
            "servicePort": vpn_client.get("servicePort", 0),
            "encryption": vpn_client.get("encryption", 0),
            "workingMode": vpn_client.get("workingMode", 0),
            "vpnConfiguration": vpn_client.get("vpnConfiguration", {"id": "", "fileName": ""})
        }
        
        # Debug logging to see what's in the payload
        # self.logger.info(f"VPN client data: {json.dumps(vpn_client, indent=2)}")
        # self.logger.info(f"Payload being sent: {json.dumps(payload, indent=2)}")
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"AccessToken={self.access_token}"
        }
        
        try:
            response = self._make_request("PATCH", url, headers=headers, json=payload)
            
            # Handle different response scenarios
            if response.status_code == 200:
                try:
                    result = response.json()
                    if result.get("errorCode") == 0:
                        status_text = "ACTIVE" if new_status else "INACTIVE"
                        self.logger.info(f"VPN client '{vpn_client['name']}' status changed to: {status_text}")
                        return True
                    else:
                        self.logger.error(f"API error: {result.get('msg')}")
                        return False
                except json.JSONDecodeError:
                    # Some successful requests may not return JSON
                    status_text = "ACTIVE" if new_status else "INACTIVE"
                    self.logger.info(f"VPN client '{vpn_client['name']}' status changed to: {status_text}")
                    return True
            else:
                self.logger.error(f"Request failed with status {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to update VPN client status: {str(e)}")
            return False
    
    def restart_vpn_client(self, site_id: str, vpn_name: str, wait_time: int = 5) -> bool:
        """Restart a VPN client by disabling, waiting, then enabling it"""
        self.logger.info(f"🔄 Restarting VPN client: {vpn_name}")
        
        # Find the VPN client
        vpn_client = self.find_vpn_client(site_id, vpn_name)
        if not vpn_client:
            self.logger.error(f"VPN client '{vpn_name}' not found")
            return False
        
        try:
            # Step 1: Disable
            self.logger.info("Step 1: Disabling VPN client...")
            if not self.update_vpn_client_status(site_id, vpn_client, False):
                self.logger.error("❌ Failed to disable VPN client")
                return False
            self.logger.info("✅ VPN client disabled successfully")
            
            # Step 2: Wait
            self.logger.info(f"Step 2: Waiting {wait_time} seconds...")
            for i in range(wait_time, 0, -1):
                print(f"  {i}...", end=" ", flush=True)
                time.sleep(1)
            print("\n")
            
            # Step 3: Enable
            self.logger.info("Step 3: Enabling VPN client...")
            if not self.update_vpn_client_status(site_id, vpn_client, True):
                self.logger.error("❌ Failed to enable VPN client")
                return False
            self.logger.info("✅ VPN client enabled successfully")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error during VPN client restart: {str(e)}")
            return False
    
    def execute_vpn_action(self, vpn_name: str, action: VPNAction) -> bool:
        """Execute the specified VPN action"""
        try:
            # Get sites and use the first one
            sites = self.get_sites()
            if not sites:
                self.logger.error("No sites found")
                return False
            
            site = sites[0]
            site_id = site["siteId"]
            site_name = site.get("name", "Unknown")
            self.logger.info(f"Using site: {site_name}")
            
            if action == VPNAction.RESTART:
                return self.restart_vpn_client(site_id, vpn_name)
            else:
                # Find VPN client
                vpn_client = self.find_vpn_client(site_id, vpn_name)
                if not vpn_client:
                    self.logger.error(f"VPN client '{vpn_name}' not found")
                    return False
                
                new_status = action == VPNAction.ENABLE
                return self.update_vpn_client_status(site_id, vpn_client, new_status)
                
        except Exception as e:
            self.logger.error(f"Error executing VPN action: {str(e)}")
            return False


def main() -> int:
    """Main function"""
    try:
        # Load configuration
        config = OmadaConfig.from_env()
        
        # Create manager instance
        manager = OmadaVPNManager(config)
        
        # Log configuration (without sensitive data)
        manager.logger.info(f"Connecting to Omada Controller at {config.base_url}")
        manager.logger.info(f"Target VPN: {config.vpn_name} (Action: {config.vpn_action.value})")
        
        # Authenticate
        manager.authenticate()
        
        # Handle token-only mode
        if config.vpn_action == VPNAction.TOKEN_ONLY:
            manager.logger.info("✅ Token generated successfully and saved to omada_token.json")
            manager.logger.info("Exiting as requested (token_only mode)")
            return 0
        
        # Execute VPN action
        success = manager.execute_vpn_action(config.vpn_name, config.vpn_action)
        
        if success:
            manager.logger.info(f"✅ Successfully {config.vpn_action.value}d VPN client '{config.vpn_name}'")
            return 0
        else:
            manager.logger.error(f"❌ Failed to {config.vpn_action.value} VPN client '{config.vpn_name}'")
            return 1
            
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())