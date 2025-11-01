# app.py
from fastapi import FastAPI, Depends, HTTPException, Body, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from datetime import datetime, timedelta
from passlib.hash import bcrypt
import boto3
from sqlalchemy import create_engine, select, and_
from sqlalchemy.orm import sessionmaker
from models import Base, Tenant, User, TenantStatus, Detection
from config import DB_URL, JWT_SECRET, JWT_ISS, AWS_REGION

app = FastAPI(title="VigiaAI Marketplace Provisioning")

# DB
engine = create_engine(DB_URL, future=True)
Session = sessionmaker(bind=engine, expire_on_commit=False, future=True)
Base.metadata.create_all(engine)

# Auth helpers
bearer = HTTPBearer()

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

# 1) Endpoint de registro Marketplace: recibe ?token=...
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

    with Session() as s, s.begin():
        tenant = s.execute(select(Tenant).where(Tenant.customer_identifier == cid)).scalar_one_or_none()
        if not tenant:
            tenant = Tenant(
                customer_identifier=cid,
                aws_account_id=aws_acct,
                product_code=product,
                status=TenantStatus.PENDING_PROFILE
            )
            s.add(tenant)
            s.flush()
        # devolvés el tenant_id para el siguiente paso (form e-mail + password)
        return {"tenant_id": tenant.id, "status": tenant.status.value}

# 2) Completar perfil: crea usuario y password
@app.post("/marketplace/complete-profile")
def complete_profile(payload: dict = Body(...)):
    tenant_id = payload.get("tenant_id")
    email = payload.get("email")
    password = payload.get("password")
    if not (tenant_id and email and password):
        raise HTTPException(status_code=400, detail="tenant_id, email, password required")

    with Session() as s, s.begin():
        t = s.get(Tenant, tenant_id)
        if not t:
            raise HTTPException(status_code=404, detail="tenant not found")

        hash_ = bcrypt.hash(password)
        user = User(tenant_id=t.id, email=email.lower().strip(), password_hash=hash_)
        s.add(user)
        t.status = TenantStatus.ACTIVE
        s.add(t)
        # emitir JWT
        token = issue_jwt(email.lower().strip(), t.id)
        return {"access_token": token, "token_type": "bearer"}

# 3) Login clásico por e-mail + password
@app.post("/auth/login")
def login(payload: dict = Body(...)):
    email, password = payload.get("email"), payload.get("password")
    with Session() as s:
        user = s.execute(select(User).where(User.email == (email or "").lower().strip())).scalar_one_or_none()
        if not user or not bcrypt.verify(password or "", user.password_hash):
            raise HTTPException(status_code=401, detail="invalid credentials")
        token = issue_jwt(user.email, user.tenant_id)
        return {"access_token": token, "token_type": "bearer"}

# 4) Endpoint del dashboard: filtra por tenant_id del JWT
@app.get("/detections")
def list_detections(ctx=Depends(require_auth)):
    tenant_id = ctx["tenant_id"]
    with Session() as s:
        rows = s.execute(
            select(Detection).where(Detection.tenant_id == tenant_id).order_by(Detection.ts.desc())
        ).scalars().all()
        return [
            {"id": r.id, "source_ip": r.source_ip, "label": r.label, "probability": r.probability, "ts": r.ts.isoformat()}
        for r in rows]
    
# creacion tenant falso para pruebas
@app.post("/dev/stub-register", status_code=status.HTTP_201_CREATED)
def dev_stub_register():
    fake_customer_id = f"dev-{uuid.uuid4()}"
    fake_aws_acct = "000000000000"
    fake_product = "DEV-PRODUCT"

    with Session() as s, s.begin():
        t = Tenant(
            customer_identifier=fake_customer_id,
            aws_account_id=fake_aws_acct,
            product_code=fake_product,
            status=TenantStatus.PENDING_PROFILE
        )
        s.add(t)
        s.flush()
        return {"tenant_id": t.id, "status": t.status.value}