# UCam Auth - University of Cambridge Authentication Library

A Python library for authenticating University of Cambridge users via OpenID Connect (OIDC) using Microsoft Entra ID.

## Usage

```python
import secrets

from ucam_auth import Auth

redirect_uri = "https://yourapp.com/callback"

auth = Auth(
    client_id="your-client-id",
    client_secret="your-client-secret",
    redirect_uri=redirect_uri
)

state = secrets.token_urlsafe(32)

auth_url = auth.get_authorization_url(state)
# Redirect the users to <auth_url>
# ...
# User is sent to <redirect_uri>?code=xxx
code = request.args.get("code")  # Get from query params
returned_state = request.args.get("state")

# Verify state for CSRF protection
if returned_state != state:
    raise ValueError("State mismatch")

# Complete authentication
tokens = auth.authenticate(code)

access_token = tokens["access_token"]
id_token = tokens["id_token"]
```

## Advanced Usage

### Group Membership

```python
from azure.core.credentials import AccessToken

tokens = auth.authenticate(code)
access_token = AccessToken(tokens["access_token"], tokens["id_token_claims"]["exp"])

groups = await auth.get_groups(access_token)

if Auth.UOC_USERS_STUDENT in groups:
    print("User is a student")
```

### Silent Token Acquisition

```python
accounts = auth.get_accounts()
if accounts:
    tokens = auth.acquire_token_silent(accounts[0])
```
