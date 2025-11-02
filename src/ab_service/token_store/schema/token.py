from datetime import datetime
from uuid import UUID

from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from pydantic import BaseModel


class CreateOAuth2TokenRequest(BaseModel):
    created_by: UUID
    tenant_id: UUID
    name: str | None = None
    oauth2_token: OAuth2Token
    expires_at: datetime | None = None
