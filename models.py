# models.py
# En DynamoDB no usamos SQLAlchemy; definimos solo enums y "schemas" (opcional).
from enum import Enum
from pydantic import BaseModel, EmailStr
from typing import List, Optional

class TenantStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PENDING_PROFILE = "PENDING_PROFILE"
    SUSPENDED = "SUSPENDED"

# Request/response models (opcionales, para tipado en FastAPI)

class CompleteProfileReq(BaseModel):
    tenant_id: str
    email: EmailStr
    password: str

class AuthLoginReq(BaseModel):
    tenant_id: str
    email: EmailStr
    password: str

class EnisRegisterReq(BaseModel):
    eni_ids: List[str]

class IngestDetectionReq(BaseModel):
    # Permite VNI o ENI; al menos uno debe venir
    vni: Optional[int] = None
    eni_id: Optional[str] = None
    source_ip: str
    label: str             # "MALWARE" / "CLEAN"
    probability: str       # "92.1%"
    ts: Optional[str] = None