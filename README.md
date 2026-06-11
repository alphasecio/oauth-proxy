# oauth-proxy

A minimal, single-user OAuth authorization proxy. Run the OAuth flow once through a small web UI, then copy the resulting access token for use in another app, script, or CLI. Supports **GitHub**, **Google**, **Microsoft**, **Auth0**, and any **custom** OAuth 2.0 provider.

## How it works

1. Configure your OAuth client credentials (via the `/config` page or environment variables).
2. Click **Sign in** to run the authorization code flow.
3. The access token is displayed on the home page for you to copy.

## Configuration

Set these via environment variables, or leave them blank and enter them at `/config`:

| Variable | Description |
|---|---|
| `OAUTH_CLIENT_ID` | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | OAuth client secret |
| `OAUTH_PROVIDER` | `github`, `google`, `microsoft`, `auth0`, or `custom` |
| `REDIRECT_URI` | Callback URL registered with your provider (e.g. `https://your-app.up.railway.app/callback`) |
| `OAUTH_SCOPE` | Optional; defaults to the provider's standard scope |
| `CUSTOM_AUTH_URL` / `CUSTOM_TOKEN_URL` | Required for `custom` / `auth0` providers (must be `https://`) |
| `OAUTH_AUDIENCE` | Optional API audience (`auth0` / `custom`) |
| `FLASK_SECRET_KEY` | Session signing key — **set this** so sessions persist across restarts |
| `DEBUG` | `False` in production |

## Run

**Docker**

```bash
docker build -t oauth-proxy .
docker run -p 5000:5000 --env-file .env oauth-proxy
```

**Local**

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://localhost:5000`.

**Railway** — [deploy from this repo](https://railway.com/?referralCode=alphasec) and set the environment variables above; `PORT` is provided automatically.

## Routes

| Route | Purpose |
|---|---|
| `/` | Login status and token |
| `/config` | Configure credentials |
| `/login` | Start the OAuth flow |
| `/callback` | OAuth redirect target |
| `/logout` | Clear the token (keeps config) |
| `/health` | Health check |

## Notes

This proxy is **single-user** by design — one operator authenticates and retrieves their own token. It does not store or scope tokens for multiple concurrent users. The token is held in the server-side session and shown in the UI for copying; deploy it somewhere only you can reach.
