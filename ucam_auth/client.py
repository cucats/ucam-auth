import jwt
import secrets
import requests
from urllib.parse import urlencode


class Auth:
    TENANT_ID = "49a50445-bdfa-4b79-ade3-547b4f3986e9"
    AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
    AUTHORIZE_ENDPOINT = f"{AUTHORITY}/oauth2/v2.0/authorize"
    TOKEN_ENDPOINT = f"{AUTHORITY}/oauth2/v2.0/token"
    JWKS_ENDPOINT = f"{AUTHORITY}/discovery/v2.0/keys"
    GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"

    UOC_USERS_STUDENT = "0cbcd7fb-1f17-48fc-ac3e-4a22131fa92d"

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._jwks_cache = None

    def get_authorization_url(self, state: str) -> str:
        scopes = ["openid", "profile", "email", "User.Read"]

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(scopes),
            "state": state,
            "prompt": "select_account",
            "domain_hint": "cam.ac.uk",
        }

        return f"{self.AUTHORIZE_ENDPOINT}?{urlencode(params)}"

    def _exchange_tokens(self, code: str) -> dict[str, str]:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }

        response = requests.post(self.TOKEN_ENDPOINT, data=data)

        if response.status_code == 200:
            return response.json()
        else:
            raise RuntimeError(
                f"Token exchange failed: [{response.status_code}] {response.text}"
            )

    def _verify_id_token(self, id_token: str) -> dict:
        try:
            if not self._jwks_cache:
                self._fetch_jwks()

            unverified_header = jwt.get_unverified_header(id_token)
            kid = unverified_header.get("kid")

            if not kid:
                raise ValueError("No key ID in token header")

            signing_key = self._get_signing_key(kid)
            if not signing_key:
                self._fetch_jwks()
                signing_key = self._get_signing_key(kid)
                if not signing_key:
                    raise ValueError("Signing key not found")

            decoded = jwt.decode(
                id_token,
                signing_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"{self.AUTHORITY}/v2.0",
                options={"verify_exp": True},
            )

            return decoded

        except jwt.ExpiredSignatureError:
            raise ValueError("ID token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid ID token: {str(e)}")

    def authenticate(self, code: str) -> dict:
        tokens = self._exchange_tokens(code)
        claims = self._verify_id_token(tokens["id_token"])
        access_token = tokens.get("access_token")

        return tokens

    def _fetch_jwks(self) -> None:
        response = requests.get(self.JWKS_ENDPOINT)
        if response.status_code != 200:
            raise RuntimeError("Failed to fetch JWKS")
        self._jwks_cache = response.json()

    def _get_signing_key(self, kid: str):
        if not self._jwks_cache:
            return None

        for key in self._jwks_cache.get("keys", []):
            if key.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        return None

    def get_groups(self, access_token: str) -> list[dict]:
        headers = {"Authorization": f"Bearer {access_token}"}

        response = requests.get(
            f"{self.GRAPH_ENDPOINT}/me/memberOf?$select=id,displayName",
            headers=headers,
        )

        if response.status_code == 200:
            groups = response.json().get("value", [])

            return [g.get("id") for g in groups]
        else:
            return []
