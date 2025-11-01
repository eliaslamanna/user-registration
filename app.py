# app.py (DynamoDB)
from fastapi import FastAPI, Depends, HTTPException, Body, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from passlib.hash import bcrypt
from datetime import datetime, timedelta
import os, uuid, random

import boto3
from boto3.dynamodb.conditions import Key, Attr

from config import (
    JWT_SECRET, JWT_ISS, AWS_REGION,
    DDB_TENANTS_TABLE, DDB_USERS_TABLE, DDB_DETECTIONS_TABLE
)

app = FastAPI(title="RansomProof Marketplace Provisioning (DynamoDB)")

# CORS (ajustá origins para tu dashboard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer = HTTPBearer()

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def issue_jwt(email: str, tenant_id: str):
    now = datetime.utcnow()
    payload = {
        "sub": email,
        "tenant_id": tenant_id,
        "iss": JWT_ISS,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=12)).timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def require_auth(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        token = creds.credentials
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
        return {"email": data["sub"], "tenant_id": data["tenant_id"]}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# --- Dynamo setup ---
ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
t_tenants = ddb.Table(DDB_TENANTS_TABLE)
t_users = ddb.Table(DDB_USERS_TABLE)
t_detections = ddb.Table(DDB_DETECTIONS_TABLE)

TENANT_STATUS_ACTIVE = "ACTIVE"
TENANT_STATUS_PENDING = "PENDING_PROFILE"
TENANT_STATUS_SUSPENDED = "SUSPENDED"

# Helpers Dynamo
def get_tenant_by_customer_identifier(customer_identifier: str):
    # Requiere GSI: gsi_customer_identifier (PK = customer_identifier)
    resp = t_tenants.query(
        IndexName="gsi_customer_identifier",
        KeyConditionExpression=Key("customer_identifier").eq(customer_identifier),
        Limit=1
    )
    items = resp.get("Items", [])
    return items[0] if items else None

def get_tenant(tenant_id: str):
    resp = t_tenants.get_item(Key={"tenant_id": tenant_id})
    return resp.get("Item")

def create_or_get_tenant(customer_identifier: str, aws_acct: str, product_code: str):
    # ¿ya existe?
    existing = get_tenant_by_customer_identifier(customer_identifier)
    if existing:
        return existing

    tenant_id = str(uuid.uuid4())
    item = {
        "tenant_id": tenant_id,
        "customer_identifier": customer_identifier,
        "aws_account_id": aws_acct,
        "product_code": product_code,
        "status": TENANT_STATUS_PENDING,
        "created_at": now_iso(),
    }
    # Condición para no pisar si justo se creó en paralelo (edge)
    t_tenants.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(tenant_id)"
    )
    return item

def put_user(tenant_id: str, email: str, password_hash: str):
    # PK=tenant_id, SK=email garantiza unicidad por tenant
    item = {
        "tenant_id": tenant_id,
        "email": email,
        "user_id": str(uuid.uuid4()),
        "password_hash": password_hash,
        "created_at": now_iso(),
    }
    t_users.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(tenant_id) AND attribute_not_exists(email)"
    )
    return item

def get_user(tenant_id: str, email: str):
    resp = t_users.get_item(Key={"tenant_id": tenant_id, "email": email})
    return resp.get("Item")

def activate_tenant(tenant_id: str):
    t_tenants.update_item(
        Key={"tenant_id": tenant_id},
        UpdateExpression="SET #s = :active",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":active": TENANT_STATUS_ACTIVE}
    )

def list_detections_by_tenant(tenant_id: str, limit: int = 100):
    resp = t_detections.query(
        KeyConditionExpression=Key("tenant_id").eq(tenant_id),
        Limit=limit,
        ScanIndexForward=False  # orden DESC por SK si lo armás como ts#uuid
    )
    return resp.get("Items", [])

# --- Endpoints ---

# 1) AWS Marketplace: /marketplace/register?token=...
@app.get("/marketplace/register")
def marketplace_register(token: str = Query(..., description="Registration token from AWS Marketplace")):
    client = boto3.client("meteringmarketplace", region_name=AWS_REGION)
    try:
        res = client.resolve_customer(RegistrationToken=token)
    except client.exceptions.InvalidTokenException:
        raise HTTPException(status_code=400, detail="Invalid registration token")
    except Exception:
        raise HTTPException(status_code=500, detail="ResolveCustomer failed")

    cid = res["CustomerIdentifier"]
    aws_acct = res["CustomerAWSAccountId"]
    product = res["ProductCode"]

    tenant = create_or_get_tenant(cid, aws_acct, product)
    return {"tenant_id": tenant["tenant_id"], "status": tenant["status"]}

# 2) Completar perfil: crea usuario y activa tenant
@app.post("/marketplace/complete-profile")
def complete_profile(payload: dict = Body(...)):
    tenant_id = payload.get("tenant_id")
    email = (payload.get("email") or "").lower().strip()
    password = payload.get("password")

    if not (tenant_id and email and password):
        raise HTTPException(status_code=400, detail="tenant_id, email, password required")

    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="tenant not found")

    hash_ = bcrypt.hash(password)
    try:
        put_user(tenant_id, email, hash_)
    except Exception as e:
        # Si falla ConditionExpression → ya existe ese email en el tenant
        raise HTTPException(status_code=409, detail="user already exists for this tenant")

    activate_tenant(tenant_id)
    token = issue_jwt(email, tenant_id)
    return {"access_token": token, "token_type": "bearer"}

# 3) Login: requiere tenant_id + email + password (recomendado con multi-tenant)
@app.post("/auth/login")
def login(payload: dict = Body(...)):
    tenant_id = payload.get("tenant_id")  # 👈 obligatorio con multi-tenant
    email = (payload.get("email") or "").lower().strip()
    password = payload.get("password") or ""

    if not (tenant_id and email):
        raise HTTPException(status_code=400, detail="tenant_id and email required")

    user = get_user(tenant_id, email)
    if not user or not bcrypt.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")

    token = issue_jwt(email, tenant_id)
    return {"access_token": token, "token_type": "bearer"}

# 4) /detections: usa tenant_id del JWT y consulta Dynamo
@app.get("/detections")
def detections(ctx=Depends(require_auth)):
    items = list_detections_by_tenant(ctx["tenant_id"], limit=200)
    # normalizar la salida (ts_key -> ts)
    out = []
    for r in items:
        out.append({
            "id": r.get("detection_id"),
            "source_ip": r.get("source_ip"),
            "label": r.get("label"),
            "probability": r.get("probability"),
            "ts": r.get("ts") or r.get("ts_key", "").split("#")[0]
        })
    return out

# ---- DEV ONLY: stub de registro sin AWS (para pruebas locales) ----
@app.post("/dev/stub-register", status_code=status.HTTP_201_CREATED)
def dev_stub_register():
    fake_customer_id = f"dev-{uuid.uuid4()}"
    fake_aws_acct = "000000000000"
    fake_product = "DEV-PRODUCT"
    t = create_or_get_tenant(fake_customer_id, fake_aws_acct, fake_product)
    return {"tenant_id": t["tenant_id"], "status": t["status"]}

# ---- DEV ONLY: seed detections para el tenant del token ----
@app.post("/dev/seed-detections")
def seed_detections(ctx=Depends(require_auth)):
    tenant_id = ctx["tenant_id"]
    batch = ddb.batch_writer(DDB_DETECTIONS_TABLE) if hasattr(ddb, "batch_writer") else None

    # si no tenés batch_writer en tu stub, usamos table.batch_writer()
    with ddb.Table(DDB_DETECTIONS_TABLE).batch_writer() as bw:
        for _ in range(15):
            ts = now_iso()
            det_id = str(uuid.uuid4())
            bw.put_item(Item={
                "tenant_id": tenant_id,
                "ts_key": f"{ts}#{det_id}",   # para ordenar por tiempo
                "detection_id": det_id,
                "source_ip": f"192.168.0.{random.randint(2,254)}",
                "label": "MALWARE",
                "probability": f"{random.randint(55,95)}.0%",
                "ts": ts
            })
    return {"inserted": 15}