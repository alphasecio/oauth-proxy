import os
import logging
import secrets
from urllib.parse import urlencode, urlparse

import dotenv
import requests
from flask import Flask, request, redirect, session, jsonify, render_template

dotenv.load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("oauth-proxy")

DEBUG = os.getenv("DEBUG", "False").strip().lower() == "true"

app = Flask(__name__)

# Session signing key. Prefer an explicit key so sessions survive restarts;
# fall back to an ephemeral key (with a warning) so the app still boots.
secret_key = os.getenv("FLASK_SECRET_KEY")
if not secret_key:
    secret_key = secrets.token_hex(32)
    logger.warning(
        "FLASK_SECRET_KEY not set; generated an ephemeral key. "
        "Sessions will not persist across restarts. Run with a single worker."
    )
app.secret_key = secret_key

app.config.update(
    SESSION_COOKIE_SECURE=not DEBUG,   # Require HTTPS for the cookie outside local dev
    SESSION_COOKIE_HTTPONLY=True,      # Block JavaScript access to the cookie
    SESSION_COOKIE_SAMESITE="Lax",     # CSRF mitigation
    PERMANENT_SESSION_LIFETIME=3600,   # Session expires after 1 hour
)

# OAuth provider configurations
PROVIDERS = {
    "github": {
        "name": "GitHub",
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "default_scope": "user:email",
        "docs_url": "https://github.com/settings/developers",
        "supports_audience": False,
        "supports_custom_urls": False,
    },
    "google": {
        "name": "Google",
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "default_scope": "openid email profile",
        "docs_url": "https://console.cloud.google.com/apis/credentials",
        "supports_audience": False,
        "supports_custom_urls": False,
    },
    "microsoft": {
        "name": "Microsoft",
        "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "default_scope": "openid email profile",
        "docs_url": "https://entra.microsoft.com/#home",
        "supports_audience": False,
        "supports_custom_urls": False,
    },
    "auth0": {
        "name": "Auth0",
        "auth_url": "",  # set via custom_auth_url: https://<domain>.auth0.com/authorize
        "token_url": "",  # set via custom_token_url: https://<domain>.auth0.com/oauth/token
        "default_scope": "openid email profile",
        "docs_url": "https://manage.auth0.com",
        "supports_audience": True,
        "supports_custom_urls": True,
    },
    "custom": {
        "name": "Custom",
        "auth_url": "",
        "token_url": "",
        "default_scope": "",
        "docs_url": "#",
        "supports_audience": True,
        "supports_custom_urls": True,
    },
}


def is_valid_https_url(value):
    """Return True only for a well-formed absolute https:// URL."""
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme == "https" and bool(parsed.netloc)


def get_config():
    """Get OAuth config from session or environment."""
    return {
        "client_id": session.get("oauth_client_id") or os.getenv("OAUTH_CLIENT_ID", ""),
        "client_secret": session.get("oauth_client_secret") or os.getenv("OAUTH_CLIENT_SECRET", ""),
        "redirect_uri": session.get("redirect_uri") or os.getenv("REDIRECT_URI", "http://localhost:5000/callback"),
        "provider": session.get("oauth_provider") or os.getenv("OAUTH_PROVIDER", "github"),
        "scope": session.get("oauth_scope") or os.getenv("OAUTH_SCOPE", ""),
        "custom_auth_url": session.get("custom_auth_url") or os.getenv("CUSTOM_AUTH_URL", ""),
        "custom_token_url": session.get("custom_token_url") or os.getenv("CUSTOM_TOKEN_URL", ""),
        "oauth_audience": session.get("oauth_audience") or os.getenv("OAUTH_AUDIENCE", ""),
    }


@app.route("/")
def home():
    """Show login status and the access token (for copying)."""
    config = get_config()
    return render_template(
        "home.html",
        authenticated="access_token" in session,
        token=session.get("access_token", ""),
        provider_name=PROVIDERS.get(config["provider"], {}).get("name", "OAuth Provider"),
        config_set=bool(config["client_id"] and config["client_secret"]),
    )


@app.route("/config", methods=["GET", "POST"])
def config():
    """Configure OAuth credentials."""
    if request.method == "POST":
        provider = request.form.get("provider", "github").strip()
        session["oauth_client_id"] = request.form.get("client_id", "").strip()
        session["oauth_client_secret"] = request.form.get("client_secret", "").strip()
        session["redirect_uri"] = request.form.get("redirect_uri", "").strip()
        session["oauth_provider"] = provider
        session["oauth_scope"] = request.form.get("scope", "").strip()

        provider_config = PROVIDERS.get(provider, {})
        if provider_config.get("supports_custom_urls"):
            session["custom_auth_url"] = request.form.get("custom_auth_url", "").strip()
            session["custom_token_url"] = request.form.get("custom_token_url", "").strip()
        if provider_config.get("supports_audience"):
            session["oauth_audience"] = request.form.get("oauth_audience", "").strip()

        return redirect("/")

    cfg = get_config()
    provider = cfg["provider"]
    provider_config = PROVIDERS.get(provider, PROVIDERS["github"])
    return render_template(
        "config.html",
        current_client_id=cfg["client_id"],
        current_client_secret=cfg["client_secret"],
        redirect_uri=cfg["redirect_uri"],
        current_provider=provider,
        current_scope=cfg["scope"] or provider_config["default_scope"],
        custom_auth_url=cfg.get("custom_auth_url", ""),
        custom_token_url=cfg.get("custom_token_url", ""),
        oauth_audience=cfg.get("oauth_audience", ""),
        providers=PROVIDERS,
    )


@app.route("/login")
def login():
    """Redirect user to OAuth provider authorization."""
    config = get_config()
    if not config["client_id"] or not config["client_secret"]:
        return redirect("/config")

    provider_config = PROVIDERS.get(config["provider"])
    if not provider_config:
        return "Invalid provider", 400

    # Resolve and validate the authorization URL
    if provider_config.get("supports_custom_urls"):
        auth_url_base = config.get("custom_auth_url", "").strip()
        if not auth_url_base:
            return f"{provider_config['name']} requires an Authorization URL — set it in config.", 400
        if not is_valid_https_url(auth_url_base):
            return "Authorization URL must be a valid https:// URL.", 400
    else:
        auth_url_base = provider_config["auth_url"]

    # Single-use CSRF state
    state = secrets.token_urlsafe(32)
    session.permanent = True
    session["oauth_state"] = state

    scope = config["scope"] or provider_config["default_scope"]

    auth_params = {
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "scope": scope,
        "state": state,
        "response_type": "code",
    }

    # Google needs this to return a refresh token
    if config["provider"] == "google":
        auth_params["access_type"] = "offline"

    # Audience — only for providers that support it
    if provider_config.get("supports_audience") and config.get("oauth_audience"):
        auth_params["audience"] = config["oauth_audience"]

    auth_url = auth_url_base + "?" + urlencode(auth_params)
    return redirect(auth_url)


@app.route("/callback")
def callback():
    """Handle OAuth callback from provider."""
    config = get_config()
    provider_config = PROVIDERS.get(config["provider"])
    if not provider_config:
        return "Invalid provider", 400

    # Verify state (present, non-empty, single-use, constant-time)
    state = request.args.get("state")
    expected_state = session.pop("oauth_state", None)
    if not state or not expected_state or not secrets.compare_digest(state, expected_state):
        return "Invalid state parameter", 400

    code = request.args.get("code")
    if not code:
        return "No code provided", 400

    # Resolve and validate the token URL
    if provider_config.get("supports_custom_urls"):
        token_url = config.get("custom_token_url", "").strip()
        if not token_url:
            return f"{provider_config['name']} requires a Token URL — set it in config.", 400
        if not is_valid_https_url(token_url):
            return "Token URL must be a valid https:// URL.", 400
    else:
        token_url = provider_config["token_url"]

    token_data = {
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "code": code,
        "redirect_uri": config["redirect_uri"],
        "grant_type": "authorization_code",
    }
    if provider_config.get("supports_audience") and config.get("oauth_audience"):
        token_data["audience"] = config["oauth_audience"]

    try:
        token_response = requests.post(
            token_url,
            headers={"Accept": "application/json"},
            data=token_data,
            timeout=10,
        )
        token_response.raise_for_status()
        token_response_data = token_response.json()
    except requests.RequestException as exc:
        logger.warning("Token exchange request failed: %s", exc)
        return "Token exchange failed", 502
    except ValueError:
        logger.warning("Token endpoint returned a non-JSON response")
        return "Invalid token response from provider", 502

    access_token = token_response_data.get("access_token")
    if not access_token:
        error = token_response_data.get("error_description") or token_response_data.get("error") or "no access_token in response"
        return f"Failed to get access token: {error}", 400

    session["access_token"] = access_token
    return redirect("/")


@app.route("/logout")
def logout():
    """Clear the token but preserve OAuth configuration."""
    config = get_config()
    session.clear()

    for value, session_key in [
        (config["client_id"], "oauth_client_id"),
        (config["client_secret"], "oauth_client_secret"),
        (config["redirect_uri"], "redirect_uri"),
        (config["provider"], "oauth_provider"),
        (config["scope"], "oauth_scope"),
        (config.get("oauth_audience"), "oauth_audience"),
        (config.get("custom_auth_url"), "custom_auth_url"),
        (config.get("custom_token_url"), "custom_token_url"),
    ]:
        if value:
            session[session_key] = value

    return redirect("/")


@app.route("/health")
def health():
    """Health check endpoint for monitoring."""
    return jsonify({"status": "ok", "service": "oauth-proxy"})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
