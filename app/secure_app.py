"""The same app after the scanner's findings are fixed.

- Secrets come from the environment (inject them from AWS Secrets Manager at deploy time).
- Every data route requires a bearer token. Only /health is public.

Day-2 upgrade: replace `require_user` with validation of an Amazon Cognito (or Entra ID)
JWT so each request carries a real user identity.
"""
import csv
import hmac
import io
import os

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI(title="Customer Portal (secure)")
bearer = HTTPBearer(auto_error=False)

CUSTOMERS = [
    {"id": 1, "name": "Asha Rao", "email": "asha@example.com", "plan": "enterprise"},
    {"id": 2, "name": "Ravi Menon", "email": "ravi@example.com", "plan": "starter"},
]


def require_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> str:
    expected = os.environ.get("API_TOKEN", "")
    if not expected or creds is None or not hmac.compare_digest(creds.credentials, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "authenticated-user"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/customers")
def list_customers(user: str = Depends(require_user)):
    return CUSTOMERS


@app.post("/customers")
def add_customer(customer: dict, user: str = Depends(require_user)):
    CUSTOMERS.append(customer)
    return customer


@app.get("/export", response_class=PlainTextResponse)
def export_csv(user: str = Depends(require_user)):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id", "name", "email", "plan"])
    writer.writeheader()
    writer.writerows(CUSTOMERS)
    return buf.getvalue()
