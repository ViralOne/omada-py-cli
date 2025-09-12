# Omada VPN Client Manager

A Python script to manage VPN clients on TP-Link Omada controllers. Supports both CLI arguments and environment variables for flexible usage.

## Features

- **Multiple VPN Support**: Manage single or multiple VPN clients in one command
- **CLI Interface**: Use command-line arguments for quick operations
- **Environment Variables**: Set defaults in `.env` file for repeated use
- **Batch Operations**: Process multiple VPNs with progress tracking and summary
- **Token Management**: Generate authentication tokens separately
- **Comprehensive Logging**: Detailed logging with optional file output

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Make the script executable:

```bash
chmod +x omada_login.py
```

3. Copy the example environment file and configure it:

```bash
cp .env.example .env
```

4. Edit `.env` with your Omada controller details:

```env
OMADA_URL=https://your-controller-ip:8043
OMADA_CLIENT_ID=your_client_id
OMADA_CLIENT_SECRET=your_client_secret
OMADA_OMADAC_ID=your_omadac_id
OMADA_USERNAME=your_username
OMADA_PASSWORD=your_password
OMADA_VPN_NAME=your_vpn_client_name
OMADA_VPN_ACTION=disable
```

### Where to get credentials

- **OMADA_URL**: Your Omada controller's web interface URL (e.g., `https://192.168.1.1:8043`)
- **OMADA_CLIENT_ID** & **OMADA_CLIENT_SECRET**: Create these in your Omada controller under Settings > Platform Integration > OpenAPI -> Add new App (Type Authorization Code)
- **OMADA_OMADAC_ID**: Settings > Platform Integration > OpenAPI (Click view on the Application) and it would be there
- **OMADA_USERNAME** & **OMADA_PASSWORD**: Your Omada controller admin credentials
- **OMADA_VPN_NAME**: The exact name of your VPN client as shown in the controller's VPN settings
- **OMADA_VPN_ACTION**: Choose `enable`, `disable`, `restart`, or `token_only`

## Usage

### CLI Mode (Recommended)

```bash
# Enable a single VPN
./omada_login.py --vpn MyVPN --action enable

# Disable multiple VPNs
./omada_login.py --vpn VPN1 VPN2 VPN3 --action disable

# Restart a VPN
./omada_login.py --vpn MyVPN --action restart

# Generate authentication token only
./omada_login.py --action token_only

# Execute action over the VPN specified in .env
./omada_login.py --action disable

# Show help
./omada_login.py --help
```

### Environment Variables Mode

Set your defaults in `.env` and run:

```bash
python omada_login.py
```

## Actions

- **enable**: Activates the VPN client(s)
- **disable**: Deactivates the VPN client(s)
- **restart**: Disables the VPN client, waits 5 seconds, then enables it (useful for reconnecting)
- **token_only**: Generates authentication token and exits (useful for testing or external tools)
