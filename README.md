# Canva Connect API - OAuth Token Generator

A simple Python desktop app for generating OAuth access tokens for the Canva Connect API. Perfect for testing integrations, customer demos, and development workflows.

## Features

- **Full OAuth 2.0 Flow**: Complete authorization code flow with PKCE support
- **Live Token Countdown**: Real-time expiry timer with color-coded warnings (green → orange → red)
- **Refresh Token Support**: Easily refresh expired tokens without re-authorization
- **Customizable Scopes**: Select exactly which permissions your integration needs
- **Copy to Clipboard**: One-click copy for access and refresh tokens
- **Clean Interface**: Simple, intuitive UI that just works

## Prerequisites

- Python 3.7+
- `tkinter` (usually pre-installed; on macOS run `brew install python-tk@3.13`)
- `requests` library

## Installation

1. Clone or download this repository

2. Create and activate a virtual environment (recommended for macOS):
```bash
python3 -m venv canva_token_env
source canva_token_env/bin/activate
```

3. Install dependencies:
```bash
pip install requests
```

4. Run the app:
```bash
python canva_token_generator.py
```

**Note**: For future sessions, activate the environment before running:
```bash
source canva_token_env/bin/activate
python canva_token_generator.py
```

## Setup

Before using the app, configure your Canva Connect API integration:

1. Go to https://www.canva.com/developers/integrations/connect-api
2. Click "Create an Integration" (or use an existing one)
3. Go to **Scopes** and select all the scopes you need
4. Navigate to **Authentication** settings
5. Add this redirect URI to URL 1: `http://127.0.0.1:8080/callback`
6. Go back to the **Configuration** tab and copy your Client ID and Client Secret

## Usage

1. **Enter Credentials**: Paste your Client ID and Client Secret
2. **Select Scopes**: Choose the permissions your integration needs
3. **Authorize**: Click "Authorize App" - your browser will open for user consent
4. **Exchange Code**: After authorization, click "Exchange Code for Token"
5. **Copy Token**: Use the generated access token in your API requests

The app displays a live countdown showing when your token will expire. When it turns orange or red, use the "Use Refresh Token" button to get a fresh token.

## Testing Your Token

Test your generated token in Postman or curl:

```bash
curl -X GET https://api.canva.com/rest/v1/users/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Use Cases

- **Customer Demos**: Show the complete OAuth flow in action
- **Development**: Quickly generate tokens for local testing
- **API Exploration**: Test different scopes and endpoints
- **Training**: Help teams understand OAuth implementation

Built for Canva Solutions Engineers and developers working with the Connect API.

---
