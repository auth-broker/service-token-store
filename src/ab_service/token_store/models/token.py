from uuid import UUID
from datetime import datetime

from ab_core.database.mixins.created_at import CreatedAtMixin
from ab_core.database.mixins.created_by import CreatedByMixin
from ab_core.database.mixins.id import IDMixin
from ab_core.database.mixins.updated_at import UpdatedAtMixin
from sqlalchemy import Column, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlmodel import Field, SQLModel


class ManagedOAuth2Token(
    IDMixin,
    CreatedAtMixin,
    CreatedByMixin,
    UpdatedAtMixin,
    SQLModel,
    table=True,
):
    __tablename__ = "token"
    __table_args__ = (
        # Enforce 1 token per (created_by, tenant_id)
        UniqueConstraint("created_by", "tenant_id", name="uq_oauth2_token_creator_conn"),
        Index("ix_oauth2_token_creator_conn", "created_by", "tenant_id"),
    )

    # Optional label for humans; no uniqueness guarantees now
    name: str | None = Field(default=None, sa_column=Column(String, nullable=True, index=True))

    # Identify which connection this token belongs to (external system/account)
    tenant_id: UUID = Field(index=True, nullable=False)

    # Token fields (stored as columns)
    access_token: str = Field(sa_column=Column(Text, nullable=False))
    id_token: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    refresh_token: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    expires_in: int = Field(sa_column=Column(Integer, nullable=False))
    scope: str | None = Field(default=None, sa_column=Column(String, nullable=True))
    token_type: str = Field(sa_column=Column(String, nullable=False))

    # Absolute expiry (UTC)
    expires_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
