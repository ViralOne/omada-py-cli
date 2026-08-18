"""Omada clients and CLIs.

- ``controller`` : internal API v2 client (cookie/CSRF) — full management.
- ``openapi``    : official OpenAPI v1 client (OAuth2) — Client-to-Site VPN.
"""
from .controller import OmadaController, create_controller
from .openapi import OmadaVPNManager, OmadaConfig, VPNAction

__all__ = [
    "OmadaController",
    "create_controller",
    "OmadaVPNManager",
    "OmadaConfig",
    "VPNAction",
]
