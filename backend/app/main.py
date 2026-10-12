from fastapi import FastAPI
from sqlalchemy import text

from app.api.auth import router as auth_router
from app.api.protected import router as protected_router
from app.config import settings
from app.db.session import engine


app = FastAPI(
    title=settings.app_name,
)

app.include_router(auth_router)
app.include_router(protected_router)


@app.get("/health")
async def health():
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))

    return {
        "status": "ok",
    }