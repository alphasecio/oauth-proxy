import os
import dotenv
import secrets
import requests
from flask import Flask, request, redirect, session, jsonify, render_template
from flask_cors import CORS

dotenv.load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

app.config.update(
    SESSION_COOKIE_SECURE=True,      # Only send cookie over HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # Prevent JavaScript access to cookie
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=3600  # Session expires after 1 hour
)

TOKEN_STORE = {}

# OAuth provider configurations
PROVIDERS = {
    'github': {
        'name': 'GitHub',
        'auth_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'default_scope': 'user:email',
        'docs_url': 'https://github.com/settings/developers',
        'supports_audience': False,
        'supports_custom_urls': False,
    },
    'google': {
        'name': 'Google',
        'auth_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'default_scope': 'openid email profile',
        'docs_url': 'https://console.cloud.google.com/apis/credentials',
        'supports_audience': False,
        'supports_custom_urls': False,
    },
    'microsoft': {
        'name': 'Microsoft',
        'auth_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        'token_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        'default_scope': 'openid email profile',
        'docs_url': 'https://entra.microsoft.com/#home',
        'supports_audience': False,
        'supports_custom_urls': False,
    },
    'auth0': {
        'name': 'Auth0',
        'auth_url': '',        # set via custom_auth_url: https://<domain>.auth0.com/authorize
        'token_url': '',       # set via custom_token_url: https://<domain>.auth0.com/oauth/token
        'default_scope': 'openid email profile',
        'docs_url': 'https://manage.auth0.com',
        'supports_audience': True,
        'supports_custom_urls': True,
    },
    'custom': {
        'name': 'Custom',
        'auth_url': '',
        'token_url': '',
        'default_scope': '',
        'docs_url': '#',
        'supports_audience': True,
        'supports_custom_urls': True,
    }
}

def get_config():
    """Get OAuth config from session or environment."""
    return {
        'client_id': session.get('oauth_client_id') or os.getenv("OAUTH_CLIENT_ID", ""),
        'client_secret': session.get('oauth_client_secret') or os.getenv("OAUTH_CLIENT_SECRET", ""),
        'redirect_uri': session.get('redirect_uri') or os.getenv("REDIRECT_URI", "http://localhost:5000/callback"),
        'provider': session.get('oauth_provider') or os.getenv("OAUTH_PROVIDER", "github"),
        'scope': session.get('oauth_scope') or os.getenv("OAUTH_SCOPE", ""),
        'custom_auth_url': session.get('custom_auth_url') or os.getenv("CUSTOM_AUTH_URL", ""),
        'custom_token_url': session.get('custom_token_url') or os.getenv("CUSTOM_TOKEN_URL", ""),
        'oauth_audience': session.get('oauth_audience') or os.getenv("OAUTH_AUDIENCE", ""),
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
        
        provider_config = PROVIDERS.get(provider, {})
        if provider_config.get('supports_custom_urls'):
            session['custom_auth_url'] = request.form.get('custom_auth_url', '').strip()
            session['custom_token_url'] = request.form.get('custom_token_url', '').strip()
        if provider_config.get('supports_audience'):
            session['oauth_audience'] = request.form.get('oauth_audience', '').strip()
            
        return redirect("/")
    
    cfg = get_config()
    provider = cfg['provider']
    provider_config = PROVIDERS.get(provider, PROVIDERS['github'])
    
    return render_template(
        'config.html',
        current_client_id=cfg['client_id'],
        current_client_secret=cfg['client_secret'],
        redirect_uri=cfg['redirect_uri'],
        current_provider=provider,
        current_scope=cfg['scope'] or provider_config['default_scope'],
        custom_auth_url=cfg.get('custom_auth_url', ''),
        custom_token_url=cfg.get('custom_token_url', ''),
        oauth_audience=cfg.get('oauth_audience', ''),
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

    # Resolve auth URL
    if provider_config.get('supports_custom_urls'):
        auth_url_base = config.get('custom_auth_url', '').strip()
        if not auth_url_base:
            return f"{provider_config['name']} requires an Authorization URL — set it in config.", 400
    else:
        auth_url_base = provider_config['auth_url']
    
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
    
    # Audience — only for providers that support it
    if provider_config.get('supports_audience') and config.get('oauth_audience'):
        auth_params['audience'] = config['oauth_audience']
 
    auth_url = auth_url_base + '?' + '&'.join(f"{k}={v}" for k, v in auth_params.items())
    return redirect(auth_url)

@app.route("/callback")
def callback():
    """Handle OAuth callback from provider."""
    config = get_config()
    provider_config = PROVIDERS.get(config['provider'])
    
    if not provider_config:
        return "Invalid provider", 400

    # Resolve token URL
    if provider_config.get('supports_custom_urls'):
        token_url = config.get('custom_token_url', '').strip()
        if not token_url:
            return f"{provider_config['name']} requires a Token URL — set it in config.", 400
    else:
        token_url = provider_config['token_url']
    
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

    # Audience — only for providers that support it
    if provider_config.get('supports_audience') and config.get('oauth_audience'):
        token_data['audience'] = config['oauth_audience']
 
    headers = {"Accept": "application/json"}
    token_response = requests.post(token_url, headers=headers, data=token_data)
    token_response_data = token_response.json()
 
    access_token = token_response_data.get("access_token")
    if not access_token:
        return f"Failed to get access token: {token_response_data}", 400
 
    # Store token keyed by API key for programmatic retrieval
    expected_key = os.getenv("OAUTH_PROXY_API_KEY")
    if expected_key:
        TOKEN_STORE[expected_key] = {
            "access_token": access_token,
            "provider": config['provider']
        }
 
    session["access_token"] = access_token
    session.pop("oauth_state", None)
 
    return redirect("/")

@app.route("/logout")
def logout():
    """Clear session and logout."""
    # Keep OAuth config but clear token
    config = get_config()

    # Clear token from TOKEN_STORE
    expected_key = os.getenv("OAUTH_PROXY_API_KEY")
    if expected_key and expected_key in TOKEN_STORE:
        del TOKEN_STORE[expected_key]
        
    session.clear()
    
    # Preserve config across logout
    for key, session_key in [
        (config['client_id'], 'oauth_client_id'),
        (config['client_secret'], 'oauth_client_secret'),
        (config['redirect_uri'], 'redirect_uri'),
        (config['provider'], 'oauth_provider'),
        (config['scope'], 'oauth_scope'),
        (config.get('oauth_audience'), 'oauth_audience'),
        (config.get('custom_auth_url'), 'custom_auth_url'),
        (config.get('custom_token_url'), 'custom_token_url'),
    ]:
        if key:
            session[session_key] = key
 
    return redirect("/")

@app.route("/health")
def health():
    """Health check endpoint for monitoring."""
    return jsonify({"status": "ok", "service": "oauth-proxy"})

@app.route("/api/token")
def get_token():
    """Get current access token via API key or session."""
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
            return jsonify({
                "error": "Not authenticated", 
                "message": "Please visit the OAuth proxy in your browser to authenticate first.",
                "login_url": request.host_url + "login"
            }), 401

        return jsonify({
            "access_token": stored_data['access_token'],
            "provider": stored_data['provider']
        })
    
    # Fall back to session-based auth
    token = session.get("access_token")
    if not token:
        return jsonify({
            "error": "Not authenticated",
            "login_url": request.host_url + "login"
        }), 401
    
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
