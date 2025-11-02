from datetime import UTC, datetime, timedelta

from ab_core.database.mixins.created_at import CreatedAtMixin
from ab_core.database.mixins.created_by import CreatedByMixin
from ab_core.database.mixins.id import IDMixin
from ab_core.database.mixins.updated_at import UpdatedAtMixin
from pydantic import BaseModel, TypeAdapter, computed_field
from sqlalchemy import JSON, Column, DateTime, Index, String, UniqueConstraint
from sqlmodel import Field, SQLModel


class OAuth2Token(BaseModel):
    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None
    expires_in: int
    scope: str | None = None
    token_type: str


class ManagedOAuth2Token(
    IDMixin,
    CreatedAtMixin,
    CreatedByMixin,
    UpdatedAtMixin,
    SQLModel,
    table=True,
):
    __tablename__ = "oauth2_token"
    __table_args__ = (
        UniqueConstraint("created_by", "name", name="uq_oauth2_token_creator_name"),
        Index("ix_oauth2_token_created_by_name", "created_by", "name"),
        Index("ix_oauth2_token_expires_at", "expires_at"),
    )

    # A human label or key for this token (unique per creator)
    name: str = Field(sa_column=Column(String, nullable=False, index=True))

    # Optional: identify where the token came from (auth server / provider)
    provider: str | None = Field(default=None, sa_column=Column(String, nullable=True, index=True))

    # Raw token payload stored as JSON (excluded from API responses)
    token_json: dict = Field(
        sa_column=Column(JSON, nullable=False),
        exclude=True,
    )

    # Absolute expiry time (UTC). Optional because some tokens might be “non-expiring”
    expires_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )

    @computed_field(return_type=OAuth2Token)
    @property
    def oauth2_token(self) -> OAuth2Token:
        return TypeAdapter(OAuth2Token).validate_python(self.token_json)

    # Helper to backfill expires_at if only expires_in is provided
    def ensure_expires_at(self) -> None:
        if self.expires_at is None:
            try:
                expires_in = self.oauth2_token.expires_in
            except Exception:
                return
            # Use created_at when available; otherwise now()
            base = self.created_at or datetime.now(UTC)
            self.expires_at = base + timedelta(seconds=expires_in)
