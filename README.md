# RansomProof – User Registration & Multi-Tenant Backend

## Arquitectura general

El backend implementa un servicio **SaaS multi-tenant** para clientes que adquieren **RansomProof** a través de **AWS Marketplace**.  
Una vez que el cliente realiza la suscripción, el sistema:

1. Recibe un token de registro desde AWS Marketplace.  
2. Crea o recupera el **tenant** correspondiente en DynamoDB.  
3. Asigna un **VNI único** para identificar el tráfico espejado (Traffic Mirroring).  
4. Permite registrar usuarios por e-mail, autenticar con JWT y recibir detecciones (por **VNI** o **ENI**).  
5. Expone endpoints REST compatibles con el dashboard de RansomProof.

El sistema es **serverless-ready**, usa **DynamoDB** como base principal y **boto3** para integrarse con los servicios de AWS (Marketplace, Dynamo, etc.).

---

## Archivos principales

### **`config.py`**
Centraliza la configuración del servicio y define los nombres de las tablas DynamoDB.

Variables expuestas:

- `JWT_SECRET`: clave para firmar los tokens JWT de autenticación.  
- `JWT_ISS`: emisor de los tokens (por defecto `"ransomproof"`).  
- `AWS_REGION`: región AWS donde corre el backend.  
- `DDB_TENANTS_TABLE`: tabla de tenants (clientes).  
- `DDB_USERS_TABLE`: tabla de usuarios finales.  
- `DDB_DETECTIONS_TABLE`: tabla de detecciones de malware.  
- `DDB_ENIS_TABLE`: tabla auxiliar que vincula ENIs con tenants.

---

### **`models.py`**
Define los **schemas** y **enumeraciones** usados en FastAPI (sin ORM, ya que se usa DynamoDB).

Incluye:

- **`TenantStatus`**  
  Enum de estado del tenant:  
  `ACTIVE | PENDING_PROFILE | SUSPENDED`.

- **`CompleteProfileReq`**  
  Entrada para completar el perfil tras la compra.  
  Campos: `tenant_id`, `email`, `password`.

- **`AuthLoginReq`**  
  Entrada para login.  
  Campos: `tenant_id`, `email`, `password`.

- **`EnisRegisterReq`**  
  Permite registrar uno o varios ENIs.  
  Campos: `eni_ids: List[str]`.

- **`IngestDetectionReq`**  
  Esquema para ingreso de detecciones desde el colector de tráfico.  
  Campos: `vni` (opcional), `eni_id` (opcional), `source_ip`, `label`, `probability`, `ts`.

---

### **`app.py`**
Contiene toda la **lógica del backend** y los endpoints FastAPI.

#### Componentes principales

- **Autenticación JWT**
  - `issue_jwt(email, tenant_id)` genera el token.  
  - `require_auth` valida el JWT e inyecta el `tenant_id` en los endpoints protegidos.

- **Integración con AWS Marketplace**
  - `GET /marketplace/register?token=...`  
    Usa `ResolveCustomer` para validar el token de compra y crear el tenant con un **VNI único**.  
    Devuelve `tenant_id`, `status` y `vni`.
  - `POST /marketplace/complete-profile`  
    Crea el usuario (e-mail + password), activa el tenant (`ACTIVE`) y devuelve el JWT inicial.

- **Autenticación de usuarios**
  - `POST /auth/login`  
    Permite ingresar con `tenant_id`, `email` y `password`.  
    Devuelve un JWT con el `tenant_id`.

- **Dashboard**
  - `GET /detections`  
    Endpoint protegido: devuelve las detecciones asociadas al `tenant_id` del token JWT.  
    Cada registro incluye `detection_id`, `eni_id`, `vni`, `source_ip`, `label`, `probability`, `ts`.

- **Gestión de ENIs**
  - `POST /enis/register`  
    Permite al cliente registrar ENIs autorizados (uno o varios).  
  - `GET /enis`  
    Lista los ENIs registrados por el tenant autenticado.  
  - `DELETE /enis/{eni_id}`  
    Elimina un ENI registrado.

- **Ingesta de detecciones**
  - `POST /ingest/detection`  
    Endpoint usado por el **colector de tráfico** de RansomProof.  
    Permite registrar detecciones de malware identificadas por:
    - **VNI** → flujo automático (recomendado).  
    - **ENI ID** → si el tráfico llega etiquetado por interfaz.  
    El backend resuelve el `tenant_id` correspondiente y guarda la detección.

- **Flujo de desarrollo / pruebas**
  - `POST /dev/stub-register`  
    Crea un tenant ficticio (`DEV-PRODUCT`) con un VNI aleatorio.  
  - `POST /dev/seed-detections`  
    Genera detecciones de ejemplo para el tenant autenticado.

---

## Esquema DynamoDB

| Tabla | Descripción | Claves | GSIs |
|--------|--------------|--------|------|
| **RansomProofTenants** | Tenants (clientes) | PK=`tenant_id` | `gsi_customer_identifier` (por AWS Marketplace)<br>`gsi_vni` (para resolver por VNI) |
| **RansomProofUsers** | Usuarios finales | PK=`tenant_id`, SK=`email` | — |
| **RansomProofTenantEnis** | ENIs registrados por tenant | PK=`tenant_id`, SK=`eni_id` | `gsi_eni_id` (para resolver tenant por ENI) |
| **RansomProofDetections** | Detecciones de malware | PK=`tenant_id`, SK=`ts_key` (`timestamp#uuid`) | — |

*(Los nombres reales pueden configurarse mediante variables de entorno.)*

---

## Variables de entorno

```bash
JWT_SECRET=super-secreto
AWS_REGION=us-east-1
DDB_TENANTS_TABLE=RansomProofTenants
DDB_USERS_TABLE=RansomProofUsers
DDB_DETECTIONS_TABLE=RansomProofDetections
DDB_ENIS_TABLE=RansomProofTenantEnis