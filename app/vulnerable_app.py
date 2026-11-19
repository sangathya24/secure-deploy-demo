"""A deliberately insecure "vibe-coded" app. DO NOT DEPLOY THIS.

It mirrors what the scanner is built to catch: credentials hardcoded in source
and routes that return sensitive data with no login.
"""
import csv
import io

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

app = FastAPI(title="Customer Portal (vibe-coded)")

# Problem 1: secrets committed to source. (This is AWS's documented example key, not a real one.)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "Sup3rS3cretPassw0rd!"

CUSTOMERS = [
    {"id": 1, "name": "Asha Rao", "email": "asha@example.com", "plan": "enterprise"},
    {"id": 2, "name": "Ravi Menon", "email": "ravi@example.com", "plan": "starter"},
]


# Problem 2: no authentication on any route that touches customer data.
@app.get("/customers")
def list_customers():
    return CUSTOMERS


@app.post("/customers")
def add_customer(customer: dict):
    CUSTOMERS.append(customer)
    return customer


@app.get("/export", response_class=PlainTextResponse)
def export_csv():
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id", "name", "email", "plan"])
    writer.writeheader()
    writer.writerows(CUSTOMERS)
    return buf.getvalue()
