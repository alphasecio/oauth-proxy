import os
import dotenv
import secrets
import requests
from flask import Flask, request, redirect, session, jsonify, render_template

dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

TOKEN_STORE = {}

# OAuth provider configurations
PROVIDERS = {
    'github': {
        'name': 'GitHub',
        'auth_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'default_scope': 'user:email',
        'docs_url': 'https://github.com/settings/developers'
    },
    'google': {
        'name': 'Google',
        'auth_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'default_scope': 'openid email profile',
        'docs_url': 'https://console.cloud.google.com/apis/credentials'
    },
    'microsoft': {
        'name': 'Microsoft Entra ID',
        'auth_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        'token_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        'default_scope': 'openid email profile',
        'docs_url': 'https://entra.microsoft.com/#home'
    },
    'gitlab': {
        'name': 'GitLab',
        'auth_url': 'https://gitlab.com/oauth/authorize',
        'token_url': 'https://gitlab.com/oauth/token',
        'default_scope': 'read_user',
        'docs_url': 'https://gitlab.com/-/profile/applications'
    },
    'linkedin': {
        'name': 'LinkedIn',
        'auth_url': 'https://www.linkedin.com/oauth/v2/authorization',
        'token_url': 'https://www.linkedin.com/oauth/v2/accessToken',
        'default_scope': 'openid profile email',
        'docs_url': 'https://www.linkedin.com/developers/apps'
    },
    'dropbox': {
        'name': 'Dropbox',
        'auth_url': 'https://www.dropbox.com/oauth2/authorize',
        'token_url': 'https://api.dropboxapi.com/oauth2/token',
        'default_scope': 'account_info.read',
        'docs_url': 'https://www.dropbox.com/developers/apps'
    },
    'discord': {
        'name': 'Discord',
        'auth_url': 'https://discord.com/api/oauth2/authorize',
        'token_url': 'https://discord.com/api/oauth2/token',
        'default_scope': 'identify email',
        'docs_url': 'https://discord.com/developers/applications'
    }
}

def get_config():
    """Get OAuth config from session or environment."""
    return {
        'client_id': session.get('oauth_client_id') or os.getenv("OAUTH_CLIENT_ID", ""),
        'client_secret': session.get('oauth_client_secret') or os.getenv("OAUTH_CLIENT_SECRET", ""),
        'redirect_uri': session.get('redirect_uri') or os.getenv("REDIRECT_URI", "http://localhost:5000/callback"),
        'provider': session.get('oauth_provider') or os.getenv("OAUTH_PROVIDER", "github"),
        'scope': session.get('oauth_scope') or os.getenv("OAUTH_SCOPE", "")
    }

@app.route("/")
def home():
    """Show login status and button."""
    config = get_config()
    authenticated = "access_token" in session
    token = session.get("access_token", "")
    provider_name = PROVIDERS.get(config['provider'], {}).get('name', 'OAuth Provider')
    
    return render_template(
        'home.html',
        authenticated=authenticated,
        token=token,
        provider_name=provider_name,
        config_set=bool(config['client_id'] and config['client_secret'])
    )

@app.route("/config", methods=["GET", "POST"])
def config():
    """Configure OAuth credentials."""
    if request.method == "POST":
        provider = request.form.get('provider', 'github').strip()
        session['oauth_client_id'] = request.form.get('client_id', '').strip()
        session['oauth_client_secret'] = request.form.get('client_secret', '').strip()
        session['redirect_uri'] = request.form.get('redirect_uri', '').strip()
        session['oauth_provider'] = provider
        session['oauth_scope'] = request.form.get('scope', '').strip()
        return redirect("/")
    
    config = get_config()
    provider = config['provider']
    provider_config = PROVIDERS.get(provider, PROVIDERS['github'])
    
    return render_template(
        'config.html',
        current_client_id=config['client_id'],
        current_client_secret=config['client_secret'],
        redirect_uri=config['redirect_uri'],
        current_provider=provider,
        current_scope=config['scope'] or provider_config['default_scope'],
        providers=PROVIDERS
    )

@app.route("/login")
def login():
    """Redirect user to OAuth provider authorization."""
    config = get_config()
    
    if not config['client_id'] or not config['client_secret']:
        return redirect("/config")
    
    provider_config = PROVIDERS.get(config['provider'])
    if not provider_config:
        return "Invalid provider", 400
    
    # Generate random state for security
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    
    # Use custom scope if provided, otherwise use default
    scope = config['scope'] or provider_config['default_scope']
    
    # Build authorization URL
    auth_params = {
        'client_id': config['client_id'],
        'redirect_uri': config['redirect_uri'],
        'scope': scope,
        'state': state,
        'response_type': 'code'
    }
    
    # Google requires specific parameter
    if config['provider'] == 'google':
        auth_params['access_type'] = 'offline'
    
    auth_url = provider_config['auth_url'] + '?' + '&'.join(
        f"{k}={v}" for k, v in auth_params.items()
    )
    
    return redirect(auth_url)

@app.route("/callback")
def callback():
    """Handle OAuth callback from provider."""
    config = get_config()
    provider_config = PROVIDERS.get(config['provider'])
    
    if not provider_config:
        return "Invalid provider", 400
    
    # Verify state to prevent CSRF
    state = request.args.get("state")
    if state != session.get("oauth_state"):
        return "Invalid state parameter", 400
    
    # Get authorization code
    code = request.args.get("code")
    if not code:
        return "No code provided", 400
    
    # Prepare token exchange request
    token_data = {
        "client_id": config['client_id'],
        "client_secret": config['client_secret'],
        "code": code,
        "redirect_uri": config['redirect_uri'],
        "grant_type": "authorization_code"
    }
    
    headers = {"Accept": "application/json"}
    
    # Exchange code for access token
    token_response = requests.post(
        provider_config['token_url'],
        headers=headers,
        data=token_data
    )
    
    token_response_data = token_response.json()
    access_token = token_response_data.get("access_token")
    
    if not access_token:
        return f"Failed to get access token: {token_response_data}", 400

    # Store token using the API key
    expected_key = os.getenv("OAUTH_PROXY_API_KEY")
    if expected_key:
        TOKEN_STORE[expected_key] = {
            "access_token": access_token,
            "provider": config['provider']
        }
    
    # Store token in session
    session["access_token"] = access_token
    session.pop("oauth_state", None)
    
    return redirect("/")

@app.route("/logout")
def logout():
    """Clear session and logout."""
    # Keep OAuth config but clear token
    config = get_config()
    session.clear()
    if config['client_id']:
        session['oauth_client_id'] = config['client_id']
    if config['client_secret']:
        session['oauth_client_secret'] = config['client_secret']
    if config['redirect_uri']:
        session['redirect_uri'] = config['redirect_uri']
    if config['provider']:
        session['oauth_provider'] = config['provider']
    if config['scope']:
        session['oauth_scope'] = config['scope']
    return redirect("/")

@app.route("/api/token")
def get_token():
    """API endpoint to get current user's token.
    
    Supports two authentication methods:
    1. Session-based (browser/same-domain requests)
    2. API key-based (CLI/server applications via X-API-Key header)
    """
    # Try API key authentication first
    api_key = request.headers.get('X-API-Key')
    if api_key:
        expected_key = os.getenv("OAUTH_PROXY_API_KEY")
        if not expected_key:
            return jsonify({"error": "API key authentication not configured"}), 500
        if api_key != expected_key:
            return jsonify({"error": "Invalid API key"}), 401
        
        stored_data = TOKEN_STORE.get(api_key)
        if not stored_data:
            # Token hasn't been saved yet (user hasn't logged in via browser since last restart)
            return jsonify({"error": "Not authenticated. Login required via browser."}), 401

        return jsonify({
            "access_token": stored_data['access_token'],
            "provider": stored_data['provider']
        })
    
    # Fall back to session-based auth
    token = session.get("access_token")
    if not token:
        return jsonify({"error": "Not authenticated"}), 401
    config = get_config()
    return jsonify({
        "access_token": token,
        "provider": config['provider']
    })

@app.route("/api/status")
def status():
    """Check authentication status."""
    config = get_config()
    return jsonify({
        "authenticated": "access_token" in session,
        "provider": config['provider']
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"🚀 OAuth Proxy running on port {port}")
    print(f"📝 Visit http://localhost:{port} to login")
    print(f"⚙️ Visit http://localhost:{port}/config to configure credentials")
    app.run(host="0.0.0.0", port=port, debug=os.getenv("DEBUG", "False") == "True")
