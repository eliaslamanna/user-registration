# user-registration

## Arquitectura del backend (FastAPI + AWS Marketplace)

### Archivos principales

- **`config.py`**  
  Centraliza la configuración del servicio. Expone:
  - `DB_URL`: cadena de conexión a la base (PostgreSQL por defecto; podés usar SQLite en dev).  
  - `JWT_SECRET`: clave para firmar los tokens.  
  - `JWT_ISS`: emisor de los JWT.  
  - `AWS_REGION`: región usada por boto3 para ResolverCustomer/Entitlements.  :contentReference[oaicite:0]{index=0}

- **`models.py`**  
  Define el **modelo de datos** con SQLAlchemy:
  - `Tenant` (multi-tenant): guarda `customer_identifier`, `aws_account_id`, `product_code` y `status`.  
  - `User`: usuario final vinculado a un `tenant` con `email` y `password_hash` (único por tenant).  
  - `Detection`: ejemplo de tabla multi-tenant para mostrar datos del dashboard.  
  - `TenantStatus`: `ACTIVE | PENDING_PROFILE | SUSPENDED`.  :contentReference[oaicite:1]{index=1}

- **`app.py`**  
  App FastAPI. Incluye:
  - **Bootstrap** de DB y sesión SQLAlchemy, y helpers de **JWT** (`issue_jwt`) y **auth** (`require_auth`). :contentReference[oaicite:2]{index=2}
  - **`GET /marketplace/register?token=...`**  
    Resuelve el token de AWS Marketplace con `boto3.client("meteringmarketplace").resolve_customer(...)`, crea (o recupera) el **tenant** y devuelve `tenant_id` + `status`. :contentReference[oaicite:3]{index=3}
  - **`POST /marketplace/complete-profile`**  
    Crea el **usuario** (email + password), activa el tenant y retorna un **JWT** con `tenant_id`. :contentReference[oaicite:4]{index=4}
  - **`POST /auth/login`**  
    Login clásico por email/password → emite JWT. :contentReference[oaicite:5]{index=5}
  - **`GET /detections`**  
    Endpoint protegido: lee `tenant_id` del JWT y devuelve solo las detecciones del tenant (multi-tenant por diseño). :contentReference[oaicite:6]{index=6}
  - **(DEV)** `POST /dev/stub-register`  
    Crea un tenant “falso” para probar el flujo sin AWS Marketplace. :contentReference[oaicite:7]{index=7}

---

### Variables de entorno (mínimas)

```bash
DB_URL=postgresql://user:pass@host:5432/dbname   # o sqlite:///./ransomproof.db para dev
JWT_SECRET=super-secreto
AWS_REGION=us-east-1