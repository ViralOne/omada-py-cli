# Omada Controller Management Tools

A collection of Python tools for managing TP-Link Omada controllers. This project provides both API v1 and v2 implementations with different capabilities and use cases.

## 📁 Project Structure

Single entrypoint — run everything via **`python3 -m omada <command>`**.

- **`omada/`** - Implementation package:
  - `__main__.py` - entrypoint (`python3 -m omada ...`)
  - `cli.py` - unified argument parsing, logging setup, `main()` dispatch
  - `controller.py` - `OmadaController` internal API v2 client (auth, requests, all `get_*`/write methods)
  - `commands.py` - `cmd_*` command handlers (v2)
  - `actions.py` - predefined custom actions (health-check, bulk-restart, network-status)
  - `openapi.py` - `OmadaVPNManager` official OpenAPI v1 client (OAuth2, Client-to-Site VPN)
  - `openapi_cli.py` - `vpn-client` subcommand (v1)
- **`probe.py`** - read-only dev tool to explore raw API endpoints (GET only)
- **`.env.example`** - Template for environment configuration
- **`requirements.txt`** - Python dependencies

### API Version Comparison

| Feature | API v1 (`vpn-client`) | API v2 (main commands) |
|---------|----------------------------|----------------------------|
| **Authentication** | OpenAPI with OAuth2 flow | Direct login with CSRF tokens |
| **Primary Use** | VPN client management | Full controller management |
| **VPN Support** | Client-to-Site VPN clients | Site-to-Site VPN configurations |
| **Credentials Required** | Client ID, Secret, Username, Password | Username, Password only |
| **CLI Interface** | Basic VPN operations | Comprehensive management tool |
| **Batch Operations** | ✅ Multiple VPN clients | ✅ Individual operations |
| **Network Monitoring** | ❌ | ✅ Devices, clients, alerts |
| **Site Management** | ✅ Basic | ✅ Full site switching |

## 🚀 Quick Start

### 1. Install

**Global command (recommended)** — installs an isolated `omada` command on your PATH:

```bash
pipx install -e .        # editable: code changes take effect immediately
```

Then run it from anywhere as `omada <command>`.

**Dev / no-install** — use a virtualenv and run via the module:

```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
python3 -m omada <command>
```

> The examples below use `python3 -m omada`; after a global install, replace that with just `omada`.

### 2. Configure Credentials

Scaffold the config file, then edit it:

```bash
omada init                    # writes ~/.config/omada/.env from a template
$EDITOR ~/.config/omada/.env
```

The CLI looks for `.env` in this order (first match wins), so `omada` works from **any directory** once `~/.config/omada/.env` exists:

```
$OMADA_ENV  →  ./.env  →  ~/.config/omada/.env  →  <project folder>/.env
```

(No global install? `cp .env.example .env` in the project folder works too.) Running any command without credentials prints these same instructions.

Config keys:

```env
# Required for both API versions
OMADA_URL=https://192.168.0.22:8043
OMADA_USERNAME=your_username
OMADA_PASSWORD=your_password

# Required only for API v1 (OpenAPI)
OMADA_CLIENT_ID=your_client_id
OMADA_CLIENT_SECRET=your_client_secret
OMADA_OMADAC_ID=your_omadac_id

# VPN configuration (for v1)
OMADA_VPN_NAME=MyVPN1,MyVPN2
OMADA_VPN_ACTION=restart
```

### 3. Choose Your Tool

**For VPN Client Management (API v1):**

```bash
python3 -m omada vpn-client --vpn MyVPN --action enable
```

**For Full Controller Management (API v2):**

```bash
python3 -m omada sites
python3 -m omada vpn list
```

## 📖 Detailed Usage

### API v1 - VPN Client Manager (`vpn-client` subcommand)

**Purpose**: Manage Client-to-Site VPN connections using the official OpenAPI

**Key Features**:

- OAuth2 authentication flow
- Batch VPN client operations
- Comprehensive logging
- Token management

**Usage Examples**:

```bash
# Enable a single VPN client
python3 -m omada vpn-client --vpn "Office VPN" --action enable

# Disable multiple VPN clients
python3 -m omada vpn-client --vpn "VPN1" "VPN2" "VPN3" --action disable

# Restart a VPN client (disable → wait → enable)
python3 -m omada vpn-client --vpn "MyVPN" --action restart

# Generate authentication token only
python3 -m omada vpn-client --action token_only

# Use environment variables
python3 -m omada vpn-client
```

### API v2 - Controller CLI Tool (main commands)

**Purpose**: Comprehensive Omada controller management using internal API v2

**Key Features**:

- Full network monitoring
- Network/VLAN, SSID, IP-group & ACL inspection
- VPN management
- Wireguard management
- Device and client management
- Alerts
- Device/Client finder
- Real-time statistics
- Predefined custom actions

**Usage Examples**:

```bash
# Network Overview
python3 -m omada sites                    # List all sites
python3 -m omada summary                  # Network summary
python3 -m omada devices                  # List devices
python3 -m omada clients --limit 20       # List clients

# Networking config
python3 -m omada networks                 # List wired networks (VLANs)
python3 -m omada ssids                    # List SSIDs
python3 -m omada groups                   # List IP / domain groups
python3 -m omada acl --type gateway       # List ACL rules (gateway|switch|eap)

# VPN Management
python3 -m omada vpn list                 # List VPN configs
python3 -m omada vpn tunnels              # Active tunnels
python3 -m omada vpn enable "MyVPN"       # Enable VPN
python3 -m omada vpn disable "MyVPN"      # Disable VPN
python3 -m omada vpn restart "MyVPN"      # Restart VPN
python3 -m omada vpn status "MyVPN"       # Check status

# Wireguard Management
python3 -m omada wireguard peers          # List WireGuard peers
python3 -m omada wireguard peer           # WireGuard peer management
python3 -m omada wireguard servers        # List WireGuard servers
python3 -m omada wireguard insights       # Show WireGuard connection insights
python3 -m omada wireguard summary        # Show WireGuard summary

# Monitoring & Troubleshooting
python3 -m omada alerts --limit 10        # Recent alerts
python3 -m omada find device "Router"     # Find device
python3 -m omada find client "Phone"      # Find client

# Predefined "custom" actions
python3 -m omada actions network-status   # Show network report (Devices, VPN Status, Alerts, Network Summary)
python3 -m omada actions vpn-health-check   # Check enabled VPNs for active tunnels, restart if no tunnels found
python3 -m omada actions vpn-bulk-restart   # Restart All VPNs

# Site-specific operations
python3 -m omada --site "Branch Office" devices
```

## 🔧 Configuration Guide

### Getting API v1 Credentials

For the `vpn-client` command, you need OpenAPI credentials:

1. **Controller Web Interface** → Settings → Platform Integration → OpenAPI
2. **Add New Application** → Type: "Authorization Code"
3. **Note down**:
   - `OMADA_CLIENT_ID` - Application Client ID
   - `OMADA_CLIENT_SECRET` - Application Client Secret
   - `OMADA_OMADAC_ID` - Controller ID (visible in application details)

## 🛠️ Development Notes

- **API v1** uses the official OpenAPI with proper OAuth2 authentication
- **API v2** uses internal controller APIs with CSRF token authentication
- Both tools support environment variables for automation
- Token files are automatically managed and cached
- SSL verification is disabled by default for self-signed certificates

## 📋 Requirements

- Python 3.11+
- TP-Link Omada Controller (tested with v6.2.x — internal API v2 / apiVer 3)
- Network access to controller
- Admin credentials for the controller
