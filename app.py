# app.py
from fastapi import FastAPI, Depends, HTTPException, Body, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from passlib.hash import bcrypt
from datetime import datetime, timedelta
import uuid, random

import boto3
from boto3.dynamodb.conditions import Key
from typing import Optional

from config import (
    JWT_SECRET, JWT_ISS, AWS_REGION,
    DDB_TENANTS_TABLE, DDB_USERS_TABLE, DDB_DETECTIONS_TABLE, DDB_ENIS_TABLE
)
from models import TenantStatus, CompleteProfileReq, AuthLoginReq, EnisRegisterReq, IngestDetectionReq

app = FastAPI(title="VigiaAI SaaS (Marketplace + DynamoDB + ENI/VNI)")

# ─────────────────────────
# CORS (ajustá origins)
# ─────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer = HTTPBearer()

# ─────────────────────────
# Utils
# ─────────────────────────
def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def issue_jwt(email: str, tenant_id: str) -> str:
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

# ─────────────────────────
# DynamoDB
# ─────────────────────────
ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
t_tenants    = ddb.Table(DDB_TENANTS_TABLE)
t_users      = ddb.Table(DDB_USERS_TABLE)
t_detections = ddb.Table(DDB_DETECTIONS_TABLE)
t_enis       = ddb.Table(DDB_ENIS_TABLE)

TENANT_STATUS_ACTIVE   = TenantStatus.ACTIVE.value
TENANT_STATUS_PENDING  = TenantStatus.PENDING_PROFILE.value
TENANT_STATUS_SUSPENDED= TenantStatus.SUSPENDED.value

# ─────────────────────────
# Tenants helpers
# ─────────────────────────
def get_tenant(tenant_id: str) -> Optional[dict]:
    resp = t_tenants.get_item(Key={"tenant_id": tenant_id})
    return resp.get("Item")

def get_tenant_by_customer_identifier(customer_identifier: str) -> Optional[dict]:
    resp = t_tenants.query(
        IndexName="gsi_customer_identifier",
        KeyConditionExpression=Key("customer_identifier").eq(customer_identifier),
        Limit=1
    )
    items = resp.get("Items", [])
    return items[0] if items else None

def get_tenant_by_vni(vni: int) -> Optional[str]:
    resp = t_tenants.query(
        IndexName="gsi_vni",
        KeyConditionExpression=Key("vni").eq(vni),
        Limit=1
    )
    items = resp.get("Items", [])
    return items[0]["tenant_id"] if items else None

def create_or_get_tenant(customer_identifier: str, aws_acct: str, product_code: str) -> dict:
    existing = get_tenant_by_customer_identifier(customer_identifier)
    if existing:
        return existing

    tenant_id = str(uuid.uuid4())
    # VNI asignado por app (simple: random en rango legible)
    vni = random.randint(1000, 999999)  # podés coordinar rango por región/cuenta

    item = {
        "tenant_id": tenant_id,
        "customer_identifier": customer_identifier,
        "aws_account_id": aws_acct,
        "product_code": product_code,
        "status": TENANT_STATUS_PENDING,
        "vni": vni,
        "created_at": now_iso(),
    }
    t_tenants.put_item(Item=item, ConditionExpression="attribute_not_exists(tenant_id)")
    return item

def activate_tenant(tenant_id: str):
    t_tenants.update_item(
        Key={"tenant_id": tenant_id},
        UpdateExpression="SET #s = :active",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":active": TENANT_STATUS_ACTIVE}
    )

# ─────────────────────────
# Users helpers
# PK = tenant_id, SK = email
# ─────────────────────────
def put_user(tenant_id: str, email: str, password_hash: str) -> dict:
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

def get_user(tenant_id: str, email: str) -> Optional[dict]:
    resp = t_users.get_item(Key={"tenant_id": tenant_id, "email": email})
    return resp.get("Item")

# ─────────────────────────
# ENIs helpers (TenantEnis)
# PK = tenant_id, SK = eni_id; GSI gsi_eni_id (PK=eni_id)
# ─────────────────────────
def register_eni(tenant_id: str, eni_id: str):
    t_enis.put_item(
        Item={
            "tenant_id": tenant_id,
            "eni_id": eni_id,
            "created_at": now_iso(),
        },
        ConditionExpression="attribute_not_exists(tenant_id) AND attribute_not_exists(eni_id)"
    )

def list_enis(tenant_id: str):
    resp = t_enis.query(KeyConditionExpression=Key("tenant_id").eq(tenant_id))
    return [it["eni_id"] for it in resp.get("Items", [])]

def delete_eni(tenant_id: str, eni_id: str):
    t_enis.delete_item(Key={"tenant_id": tenant_id, "eni_id": eni_id})

def get_tenant_by_eni(eni_id: str) -> Optional[str]:
    resp = t_enis.query(
        IndexName="gsi_eni_id",
        KeyConditionExpression=Key("eni_id").eq(eni_id),
        Limit=1
    )
    items = resp.get("Items", [])
    return items[0]["tenant_id"] if items else None

# ─────────────────────────
# Detections helpers
# PK = tenant_id, SK = ts_key (e.g. "2025-11-01T20:30:00Z#<uuid>")
# ─────────────────────────
def list_detections_by_tenant(tenant_id: str, limit: int = 200):
    resp = t_detections.query(
        KeyConditionExpression=Key("tenant_id").eq(tenant_id),
        Limit=limit,
        ScanIndexForward=False,  # DESC
    )
    return resp.get("Items", [])

def put_detection(tenant_id: str, ts: str, data: dict):
    det_id = str(uuid.uuid4())
    item = {
        "tenant_id": tenant_id,
        "ts_key": f"{ts}#{det_id}",
        "detection_id": det_id,
        **data,   # incluye: eni_id? vni? source_ip, label, probability, ts, etc.
    }
    t_detections.put_item(Item=item)
    return item

# ─────────────────────────
# Endpoints públicos (SaaS)
# ─────────────────────────

# 1) AWS Marketplace → reg URL: /marketplace/register?token=...
@app.get("/marketplace/register")
def marketplace_register(token: str = Query(..., description="Registration token from AWS Marketplace")):
    client = boto3.client("meteringmarketplace", region_name=AWS_REGION)
    try:
        res = client.resolve_customer(RegistrationToken=token)
    except client.exceptions.InvalidTokenException:
        raise HTTPException(status_code=400, detail="Invalid registration token")
    except Exception:
        raise HTTPException(status_code=500, detail="ResolveCustomer failed")

    cid      = res["CustomerIdentifier"]
    aws_acct = res["CustomerAWSAccountId"]
    product  = res["ProductCode"]

    tenant = create_or_get_tenant(cid, aws_acct, product)
    # Podrías mostrar el VNI en tu UI si querés que el cliente lo use al crear la Mirror Session
    return {"tenant_id": tenant["tenant_id"], "status": tenant["status"], "vni": tenant["vni"]}

# 2) Completar perfil: email + password → activa tenant y emite JWT
@app.post("/marketplace/complete-profile")
def complete_profile(req: CompleteProfileReq):
    tenant = get_tenant(req.tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="tenant not found")

    hash_ = bcrypt.hash(req.password)
    try:
        put_user(req.tenant_id, req.email.lower().strip(), hash_)
    except Exception:
        raise HTTPException(status_code=409, detail="user already exists for this tenant")

    activate_tenant(req.tenant_id)
    token = issue_jwt(req.email.lower().strip(), req.tenant_id)
    return {"access_token": token, "token_type": "bearer"}

# 3) Login multi-tenant (requiere tenant_id)
@app.post("/auth/login")
def login(req: AuthLoginReq):
    user = get_user(req.tenant_id, req.email.lower().strip())
    if not user or not bcrypt.verify(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")
    token = issue_jwt(req.email.lower().strip(), req.tenant_id)
    return {"access_token": token, "token_type": "bearer"}

# 4) Dashboard: listar detecciones del tenant del JWT
@app.get("/detections")
def detections(ctx=Depends(require_auth)):
    items = list_detections_by_tenant(ctx["tenant_id"], limit=200)
    out = []
    for r in items:
        out.append({
            "id": r.get("detection_id"),
            "eni_id": r.get("eni_id"),
            "vni": r.get("vni"),
            "source_ip": r.get("source_ip"),
            "label": r.get("label"),
            "probability": r.get("probability"),
            "ts": r.get("ts") or r.get("ts_key", "").split("#")[0]
        })
    return out

# ─────────────────────────
# Gestión de ENIs por el cliente (UI)
# ─────────────────────────
@app.post("/enis/register")
def enis_register(req: EnisRegisterReq, ctx=Depends(require_auth)):
    tenant_id = ctx["tenant_id"]
    if not req.eni_ids:
        raise HTTPException(status_code=400, detail="eni_ids required")
    inserted, skipped = 0, 0
    for eni in req.eni_ids:
        try:
            register_eni(tenant_id, eni)
            inserted += 1
        except Exception:
            skipped += 1  # ya existía
    return {"inserted": inserted, "skipped": skipped}

@app.get("/enis")
def enis_list(ctx=Depends(require_auth)):
    return {"eni_ids": list_enis(ctx["tenant_id"])}

@app.delete("/enis/{eni_id}")
def enis_delete(eni_id: str, ctx=Depends(require_auth)):
    delete_eni(ctx["tenant_id"], eni_id)
    return {"deleted": eni_id}

# ─────────────────────────
# Ingest de detecciones (colector/analizador)
# Permite identificar tenant por VNI (recomendado) o por ENI.
# Proteger con API key / IAM según tu despliegue.
# ─────────────────────────
@app.post("/ingest/detection")
def ingest_detection(req: IngestDetectionReq = Body(...)):
    if not (req.vni or req.eni_id):
        raise HTTPException(status_code=400, detail="vni or eni_id required")

    tenant_id = None
    if req.vni:
        tenant_id = get_tenant_by_vni(req.vni)
    if not tenant_id and req.eni_id:
        tenant_id = get_tenant_by_eni(req.eni_id)

    if not tenant_id:
        raise HTTPException(status_code=403, detail="unknown VNI/ENI; register or configure first")

    ts = req.ts or now_iso()
    put_detection(tenant_id, ts, {
        "eni_id": req.eni_id,
        "vni": req.vni,
        "source_ip": req.source_ip,
        "label": req.label,
        "probability": req.probability,
        "ts": ts
    })
    return {"stored": True, "tenant_id": tenant_id, "ts": ts}

# ─────────────────────────
# DEV helpers: stub + seed
# ─────────────────────────
@app.post("/dev/stub-register", status_code=status.HTTP_201_CREATED)
def dev_stub_register():
    fake_customer_id = f"dev-{uuid.uuid4()}"
    fake_aws_acct = "000000000000"
    fake_product = "DEV-PRODUCT"
    t = create_or_get_tenant(fake_customer_id, fake_aws_acct, fake_product)
    return {"tenant_id": t["tenant_id"], "status": t["status"], "vni": t["vni"]}

@app.post("/dev/seed-detections")
def seed_detections(ctx=Depends(require_auth)):
    tenant_id = ctx["tenant_id"]
    enis = list_enis(tenant_id)
    if not enis:
        register_eni(tenant_id, "eni-FAKEDEV123456")

    # tomamos VNI del tenant
    tenant = get_tenant(tenant_id)
    vni = tenant.get("vni")

    with t_detections.batch_writer() as bw:
        for _ in range(15):
            ts = now_iso()
            det_id = str(uuid.uuid4())
            bw.put_item(Item={
                "tenant_id": tenant_id,
                "ts_key": f"{ts}#{det_id}",
                "detection_id": det_id,
                "eni_id": enis[0],
                "vni": vni,
                "source_ip": f"192.168.0.{random.randint(2,254)}",
                "label": "MALWARE",
                "probability": f"{random.randint(55,95)}.0%",
                "ts": ts
            })
    return {"inserted": 15}