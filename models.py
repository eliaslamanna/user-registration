# models.py
from datetime import datetime
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum, UniqueConstraint
import enum, uuid

Base = declarative_base()

def uid(): return str(uuid.uuid4())

class TenantStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    PENDING_PROFILE = "PENDING_PROFILE"
    SUSPENDED = "SUSPENDED"

class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True, default=uid)
    customer_identifier = Column(String, unique=True, nullable=False)
    aws_account_id = Column(String, nullable=False)
    product_code = Column(String, nullable=False)
    status = Column(Enum(TenantStatus), default=TenantStatus.PENDING_PROFILE, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=uid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
    email = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint('tenant_id', 'email', name='uq_user_email_per_tenant'),)

# ejemplo de tabla de detecciones multi-tenant
class Detection(Base):
    __tablename__ = "detections"
    id = Column(String, primary_key=True, default=uid)
    tenant_id = Column(String, ForeignKey("tenants.id"), nullable=False)
    source_ip = Column(String, nullable=False)
    label = Column(String, nullable=False)  # MALWARE / CLEAN
    probability = Column(String, nullable=False)
    ts = Column(DateTime, default=datetime.utcnow)