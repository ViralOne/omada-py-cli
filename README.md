# Omada Controller Management Tools

A collection of Python tools for managing TP-Link Omada controllers. This project provides both API v1 and v2 implementations with different capabilities and use cases.

## 📁 Project Structure

### Core Files

- **`omada_api_v1.py`** - OpenAPI v1 implementation for VPN client management
- **`omada_api_v2.py`** - Internal API v2 implementation with comprehensive CLI tool
- **`.env.example`** - Template for environment configuration
- **`requirements.txt`** - Python dependencies

### API Version Comparison

| Feature | API v1 (`omada_api_v1.py`) | API v2 (`omada_api_v2.py`) |
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

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your controller details:

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
python3 omada_api_v1.py --vpn MyVPN --action enable
```

**For Full Controller Management (API v2):**

```bash
python3 omada_api_v2.py sites
python3 omada_api_v2.py vpn list
```

## 📖 Detailed Usage

### API v1 - VPN Client Manager (`omada_api_v1.py`)

**Purpose**: Manage Client-to-Site VPN connections using the official OpenAPI

**Key Features**:

- OAuth2 authentication flow
- Batch VPN client operations
- Comprehensive logging
- Token management

**Usage Examples**:

```bash
# Enable a single VPN client
python3 omada_api_v1.py --vpn "Office VPN" --action enable

# Disable multiple VPN clients
python3 omada_api_v1.py --vpn "VPN1" "VPN2" "VPN3" --action disable

# Restart a VPN client (disable → wait → enable)
python3 omada_api_v1.py --vpn "MyVPN" --action restart

# Generate authentication token only
python3 omada_api_v1.py --action token_only

# Use environment variables
python3 omada_api_v1.py
```

### API v2 - Controller CLI Tool (`omada_api_v2.py`)

**Purpose**: Comprehensive Omada controller management using internal API v2

**Key Features**:

- Full network monitoring
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
python3 omada_api_v2.py sites                    # List all sites
python3 omada_api_v2.py summary                  # Network summary
python3 omada_api_v2.py devices                  # List devices
python3 omada_api_v2.py clients --limit 20       # List clients

# VPN Management
python3 omada_api_v2.py vpn list                 # List VPN configs
python3 omada_api_v2.py vpn tunnels              # Active tunnels
python3 omada_api_v2.py vpn enable "MyVPN"       # Enable VPN
python3 omada_api_v2.py vpn disable "MyVPN"      # Disable VPN
python3 omada_api_v2.py vpn restart "MyVPN"      # Restart VPN
python3 omada_api_v2.py vpn status "MyVPN"       # Check status

# Wireguard Management
python3 omada_api_v2.py wireguard peers          # List WireGuard peers
python3 omada_api_v2.py wireguard peer           # WireGuard peer management
python3 omada_api_v2.py wireguard servers        # List WireGuard servers
python3 omada_api_v2.py wireguard insights       # Show WireGuard connection insights
python3 omada_api_v2.py wireguard summary        # Show WireGuard summary

# Monitoring & Troubleshooting
python3 omada_api_v2.py alerts --limit 10        # Recent alerts
python3 omada_api_v2.py find device "Router"     # Find device
python3 omada_api_v2.py find client "Phone"      # Find client

# Predefined "custom" actions
python3 omada_api_v2.py actions network-status   # Show network report (Devices, VPN Status, Alerts, Network Summary)
python3 omada_api_v2.py actions vpn-health-check   # Check enabled VPNs for active tunnels, restart if no tunnels found
python3 omada_api_v2.py actions vpn-bulk-restart   # Restart All VPNs

# Site-specific operations
python3 omada_api_v2.py --site "Branch Office" devices
```

## 🔧 Configuration Guide

### Getting API v1 Credentials

For `omada_api_v1.py`, you need OpenAPI credentials:

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
- TP-Link Omada Controller (tested with v5.x)
- Network access to controller
- Admin credentials for the controller
