"""OIDC authentication client for University of Cambridge via Microsoft Entra ID."""

from typing import ClassVar

from azure.core.credentials import AccessToken, TokenCredential
from msal import ConfidentialClientApplication, Prompt
from msgraph.graph_service_client import GraphServiceClient


class Auth:
    """University of Cambridge OIDC authentication via Microsoft Entra ID."""

    TENANT_ID = "49a50445-bdfa-4b79-ade3-547b4f3986e9"
    AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
    UOC_USERS_STUDENT = "0cbcd7fb-1f17-48fc-ac3e-4a22131fa92d"
    DEFAULT_SCOPES: ClassVar[list[str]] = ["openid", "profile", "email", "User.Read"]

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str) -> None:
        """Initialize with Azure app registration credentials."""
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

        self.app = ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=Auth.AUTHORITY,
        )

    def get_authorization_url(self, state: str, scopes: list[str] | None = None) -> str:
        """Return the URL to redirect users to for login."""
        if scopes is None:
            scopes = Auth.DEFAULT_SCOPES

        return self.app.get_authorization_request_url(
            scopes=scopes,
            redirect_uri=self.redirect_uri,
            state=state,
            prompt=Prompt.SELECT_ACCOUNT,
            domain_hint="cam.ac.uk",
        )

    def authenticate(self, code: str, scopes: list[str] | None = None) -> dict:
        """Exchange an authorization code for tokens."""
        if scopes is None:
            scopes = Auth.DEFAULT_SCOPES

        result = self.app.acquire_token_by_authorization_code(
            code=code,
            scopes=scopes,
            redirect_uri=self.redirect_uri,
        )

        if "error" in result:
            msg = (
                f"Token exchange failed: {result['error']}: "
                f"{result['error_description']}"
            )
            raise RuntimeError(msg)

        return result

    async def get_groups(self, access_token: AccessToken) -> list[str]:
        """Return the group IDs the user is a member of via MS Graph."""

        class Token(TokenCredential):
            def __init__(self, access_token: AccessToken) -> None:
                self.access_token = access_token

            def get_token(
                self,
                *_scopes: str,
                **_kwargs: object,
            ) -> AccessToken:
                return self.access_token

        credential = Token(access_token)

        client = GraphServiceClient(credential)

        member_of = await client.me.member_of.get()

        if member_of and member_of.value:
            return [
                group.id
                for group in member_of.value
                if hasattr(group, "id") and group.id is not None
            ]
        return []

    def acquire_token_silent(
        self,
        account: dict,
        scopes: list[str] | None = None,
    ) -> dict | None:
        """Acquire a token silently from the cache."""
        if scopes is None:
            scopes = self.DEFAULT_SCOPES

        return self.app.acquire_token_silent(
            scopes=scopes,
            account=account,
        )

    def get_accounts(self) -> list:
        """Return accounts in the token cache."""
        return self.app.get_accounts()
