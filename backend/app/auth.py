import os
import httpx
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    supabase_url = os.environ["NEXT_PUBLIC_SUPABASE_URL"]
    service_role_key = os.environ["SUPABASE_JWT_SECRET"]

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{supabase_url}/auth/v1/user",
            headers={
                "Authorization": f"Bearer {token}",
                "apikey": service_role_key,
            },
        )

    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id: str = resp.json().get("id", "")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user_id
