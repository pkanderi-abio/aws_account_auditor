from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
import httpx
import os

router = APIRouter()


class SignupRequest(BaseModel):
    email: EmailStr
    password: str


@router.post("/signup")
async def signup(body: SignupRequest):
    supabase_url = os.environ["NEXT_PUBLIC_SUPABASE_URL"]
    service_role_key = os.environ["SUPABASE_JWT_SECRET"]

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{supabase_url}/auth/v1/admin/users",
            headers={
                "Authorization": f"Bearer {service_role_key}",
                "apikey": service_role_key,
                "Content-Type": "application/json",
            },
            json={
                "email": body.email,
                "password": body.password,
                "email_confirm": True,
            },
        )

    if resp.status_code not in (200, 201):
        detail = resp.json().get("message") or resp.json().get("msg") or resp.text
        raise HTTPException(status_code=400, detail=detail)

    return {"message": "account created"}
