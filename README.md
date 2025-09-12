# Omada VPN Client Manager

A simple Python script to manage VPN clients on TP-Link Omada controllers.

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Copy the example environment file and configure it:

```bash
cp .env.example .env
```

3. Edit `.env` with your Omada controller details:

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

3.5 Where to get them:

- **OMADA_URL**: Your Omada controller's web interface URL (e.g., `https://192.168.1.1:8043`)
- **OMADA_CLIENT_ID** & **OMADA_CLIENT_SECRET**: Create these in your Omada controller under Settings > Platform Integration > OpenAPI -> Add new App (Type Authorization Code)
- **OMADA_OMADAC_ID**: Settings > Platform Integration > OpenAPI (Click view on the Application) and it would be there
- **OMADA_USERNAME** & **OMADA_PASSWORD**: Your Omada controller admin credentials
- **OMADA_VPN_NAME**: The exact name of your VPN client as shown in the controller's VPN settings
- **OMADA_VPN_ACTION**: Choose `enable`, `disable`, or `restart` based on what you want to do

## Usage

Simply run the script:

```bash
python omada_login.py
```

The script will:

1. Connect to your Omada controller
2. List all VPN clients
3. Enable or disable the specified VPN client based on `OMADA_VPN_ACTION`

## Configuration Options

- `OMADA_VPN_ACTION`: Set to `enable`, `disable`, or `restart` (default: `restart`)
- `OMADA_VPN_NAME`: Name of the VPN client to manage

## Logging Options

- `OMADA_LOG_TO_FILE`: Set to `true` to save logs to file (default: `false`)

## Actions

- **enable**: Activates the VPN client
- **disable**: Deactivates the VPN client  
- **restart**: Disables the VPN client, waits 5 seconds, then enables it (useful for reconnecting)
- **token_only**: Generates a new token and exists the script