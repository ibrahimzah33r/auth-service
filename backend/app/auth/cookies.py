from fastapi import Response

from app.config import settings


def set_refresh_cookie(
    response: Response,
    refresh_token: str,
) -> None:
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=refresh_token,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        max_age=(
            settings.refresh_token_expire_days
            * 24
            * 60
            * 60
        ),
        path="/auth",
    )


def clear_refresh_cookie(
    response: Response,
) -> None:
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path="/auth",
    )