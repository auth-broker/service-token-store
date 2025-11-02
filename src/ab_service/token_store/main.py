"""Main application for the OAuth2 Token Service."""

from contextlib import asynccontextmanager
from typing import Annotated

from ab_core.alembic_auto_migrate.service import AlembicAutoMigrate
from ab_core.database.databases import Database
from ab_core.dependency import Depends, inject
from ab_core.logging.config import LoggingConfig
from ab_core.sqlalchemy_fastapi_http_exceptions import register_database_exception_handlers
from fastapi import FastAPI

from ab_service.token_store.routes.token import router as token_router


@inject
@asynccontextmanager
async def lifespan(
    _app: FastAPI,
    _db: Annotated[Database, Depends(Database, persist=True)],  # cold start load db into cache
    logging_config: Annotated[LoggingConfig, Depends(LoggingConfig, persist=True)],
    alembic_auto_migrate: Annotated[AlembicAutoMigrate, Depends(AlembicAutoMigrate, persist=True)],
):
    """Lifespan context manager to handle startup and shutdown events."""
    logging_config.apply()
    alembic_auto_migrate.run()
    yield


app = FastAPI(lifespan=lifespan)
register_database_exception_handlers(app)
app.include_router(token_router)
