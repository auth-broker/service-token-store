"""OAuth2 token API routes (CRD by (created_by, tenant_id) + by id)."""

from typing import Annotated
from uuid import UUID

from ab_core.database.session_context import db_session_async
from fastapi import APIRouter, HTTPException, Query
from fastapi import Depends as FDepends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from ab_service.token_store.models.token import ManagedOAuth2Token
from ab_service.token_store.schema.token import CreateOAuth2TokenRequest

router = APIRouter(prefix="/oauth2-token", tags=["OAuth2 Token"])


@router.get("", response_model=ManagedOAuth2Token)
async def get_by_connection(
    created_by: UUID = Query(...),
    tenant_id: UUID = Query(...),
    db_session: Annotated[AsyncSession, FDepends(db_session_async)] = None,
):
    stmt = (
        select(ManagedOAuth2Token)
        .where(
            ManagedOAuth2Token.created_by == created_by,
            ManagedOAuth2Token.tenant_id == tenant_id,
        )
        .limit(1)
    )
    row = (await db_session.execute(stmt)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="OAuth2 token not found for this connection.")
    return row


@router.post("", response_model=ManagedOAuth2Token, status_code=201)
async def create(
    request: CreateOAuth2TokenRequest,
    db_session: Annotated[AsyncSession, FDepends(db_session_async)],
):
    t = request.oauth2_token
    row = ManagedOAuth2Token(
        name=request.name,
        created_by=request.created_by,
        tenant_id=request.tenant_id,
        access_token=t.access_token.get_secret_value(),
        id_token=t.id_token.get_secret_value() if t.id_token else None,
        refresh_token=t.refresh_token.get_secret_value() if t.refresh_token else None,
        expires_in=t.expires_in,
        scope=t.scope,
        token_type=t.token_type,
        expires_at=request.expires_at,
    )

    db_session.add(row)
    await db_session.flush()
    return row


@router.delete("", status_code=204)
async def delete_by_connection(
    created_by: UUID = Query(...),
    tenant_id: UUID = Query(...),
    db_session: Annotated[AsyncSession, FDepends(db_session_async)] = None,
):
    stmt = select(ManagedOAuth2Token).where(
        ManagedOAuth2Token.created_by == created_by,
        ManagedOAuth2Token.tenant_id == tenant_id,
    )
    row = (await db_session.execute(stmt)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="OAuth2 token not found for this connection.")
    await db_session.delete(row)
    await db_session.flush()
    return None


@router.get("/{id}", response_model=ManagedOAuth2Token)
async def get_one(
    id: UUID,
    db_session: Annotated[AsyncSession, FDepends(db_session_async)],
):
    row = await db_session.get(ManagedOAuth2Token, id)
    if not row:
        raise HTTPException(status_code=404, detail="OAuth2 token not found.")
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
