from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


# Mirror the internal model for the request type
class OAuth2Token(BaseModel):
    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None
    expires_in: int
    scope: str | None = None
    token_type: str


class CreateOAuth2TokenRequest(BaseModel):
    created_by: UUID
    name: str
    provider: str | None = None
    oauth2_token: OAuth2Token
    # Optional absolute expiry. If omitted, we’ll compute from created_at + expires_in.
    expires_at: datetime | None = None
