"""OAuth2 token API routes."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from ab_core.database.session_context import db_session_async
from fastapi import APIRouter, HTTPException
from fastapi import Depends as FDepends
from pydantic import TypeAdapter
from sqlalchemy.ext.asyncio import AsyncSession

from ab_service.token_store.models.token import ManagedOAuth2Token, OAuth2Token
from ab_service.token_store.schema.token import CreateOAuth2TokenRequest

router = APIRouter(prefix="/oauth2-token", tags=["OAuth2 Token"])


@router.get("/schema")
async def get_schema():
    """Return the OAuth2Token Pydantic schema for dynamic forms."""
    return TypeAdapter(OAuth2Token).json_schema()


@router.get("/{id}", response_model=ManagedOAuth2Token)
async def get_one(
    id: UUID,
    db_session: Annotated[AsyncSession, FDepends(db_session_async)],
):
    row = await db_session.get(ManagedOAuth2Token, id)
    if not row:
        raise HTTPException(status_code=404, detail="OAuth2 token not found.")
    return row


@router.post("", response_model=ManagedOAuth2Token, status_code=201)
async def create(
    request: CreateOAuth2TokenRequest,
    db_session: Annotated[AsyncSession, FDepends(db_session_async)],
):
    row = ManagedOAuth2Token(
        name=request.name,
        provider=request.provider,
        token_json=request.oauth2_token.model_dump(mode="json"),
        created_by=request.created_by,
        expires_at=request.expires_at,
    )

    # If expires_at not supplied, compute from created_at + expires_in
    # created_at is set on flush by CreatedAtMixin; if missing, fallback to now().
    # We'll compute here based on "now" (UTC), then CreatedAtMixin will set created_at anyway.
    if row.expires_at is None and request.oauth2_token.expires_in:
        base = datetime.now(UTC)
        row.expires_at = base.fromtimestamp(base.timestamp()) + (
            request.oauth2_token.expires_in * 1
        )  # mypy-friendly, explicit calc
        # better:
        from datetime import timedelta

        row.expires_at = base + timedelta(seconds=request.oauth2_token.expires_in)

    db_session.add(row)
    await db_session.flush()
    return row


@router.delete("/{id}", status_code=204)
async def delete_one(
    id: UUID,
    db_session: Annotated[AsyncSession, FDepends(db_session_async)],
):
    row = await db_session.get(ManagedOAuth2Token, id)
    if not row:
        raise HTTPException(status_code=404, detail="OAuth2 token not found.")
    await db_session.delete(row)
    await db_session.flush()
    return None
