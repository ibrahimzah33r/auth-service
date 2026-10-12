import hashlib

from fastapi import HTTPException, status

from app.config import settings
from app.db.redis import redis_client


def email_key(email: str) -> str:
    return hashlib.sha256(
        email.lower().encode("utf-8")
    ).hexdigest()


async def increment_counter(
    key: str,
    window_seconds: int,
) -> int:
    count = await redis_client.incr(key)

    if count == 1:
        await redis_client.expire(
            key,
            window_seconds,
        )

    return count


async def check_login_ip_limit(
    client_ip: str,
) -> None:
    key = f"rate:login:ip:{client_ip}"

    count = await increment_counter(
        key,
        settings.login_ip_window_seconds,
    )

    if count > settings.login_ip_limit:
        ttl = await redis_client.ttl(key)

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
            headers={
                "Retry-After": str(max(ttl, 1)),
            },
        )


async def check_login_account_limit(
    email: str,
) -> None:
    key = (
        "rate:login:account:"
        f"{email_key(email)}"
    )

    value = await redis_client.get(key)

    failures = int(value or 0)

    if failures >= settings.login_account_limit:
        ttl = await redis_client.ttl(key)

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
            headers={
                "Retry-After": str(max(ttl, 1)),
            },
        )


async def record_login_failure(
    email: str,
) -> None:
    key = (
        "rate:login:account:"
        f"{email_key(email)}"
    )

    await increment_counter(
        key,
        settings.login_account_window_seconds,
    )


async def clear_login_failures(
    email: str,
) -> None:
    key = (
        "rate:login:account:"
        f"{email_key(email)}"
    )

    await redis_client.delete(key)