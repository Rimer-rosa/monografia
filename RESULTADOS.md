# RESULTADOS.md
## Vulnerabilidades, Evidencias y Mitigaciones

**Proyecto:** Análisis de Vulnerabilidades — Diesel Soft SRL  
**Total vulnerabilidades:** 8 activas (5 explotadas · 3 verificadas)  
**CVSS máximo:** 9.9 (V1)

---

## Índice

1. [Resumen ejecutivo](#resumen-ejecutivo)
2. [V1 — Backend /inv-api sin autenticación](#v1--backend-inv-api-sin-autenticación-cvss-99)
3. [V2 — PDFs con URLs permanentes](#v2--pdfs-con-urls-permanentes-cvss-81)
4. [V3 — Credenciales Firebase expuestas](#v3--credenciales-firebase-expuestas-cvss-75)
5. [V4 — Firebase Storage público](#v4--firebase-storage-público-cvss-75)
6. [V5 — Sin rate limiting](#v5--sin-rate-limiting-cvss-75)
7. [V6 — TLS 1.0 y 1.1 activos](#v6--tls-10-y-11-activos-cvss-65)
8. [V7 — Headers HTTP faltantes](#v7--headers-http-faltantes-cvss-53)
9. [V8 — Debug/Swagger en producción](#v8--debugswagger-en-producción-cvss-53)
10. [Mitigaciones](#mitigaciones)
11. [Plan de implementación](#plan-de-implementación)

---

## Resumen Ejecutivo

| ID | Vulnerabilidad | CVSS | Severidad | Estado |
|---|---|---|---|---|
| **V1** | Backend /inv-api sin autenticación (76+ endpoints) | **9.9** | 🔴 CRÍTICA | Explotada |
| **V2** | PDFs con URLs permanentes (expiración año 2491) | **8.1** | 🟠 ALTA | Explotada |
| **V3** | Credenciales Firebase hardcodeadas en código fuente | **7.5** | 🟠 ALTA | Verificada |
| **V4** | Firebase Storage accesible sin autenticación | **7.5** | 🟠 ALTA | Explotada |
| **V5** | Ausencia de rate limiting (riesgo DoS) | **7.5** | 🟠 ALTA | Verificada |
| **V6** | TLS 1.0 y TLS 1.1 deprecados activos | **6.5** | 🟡 MEDIA | Verificada |
| **V7** | Headers de seguridad HTTP faltantes (5 headers) | **5.3** | 🟡 MEDIA | Verificada |
| **V8** | Debug/Swagger activos en producción | **5.3** | 🟡 MEDIA | Verificada |

### Impacto sobre la Tríada CIA

| Vulnerabilidad | Confidencialidad | Integridad | Disponibilidad |
|---|---|---|---|
| V1 | ✗ Comprometida | ✗ Comprometida | ✗ Comprometida |
| V2 | ✗ Comprometida | — | — |
| V3 | ✗ Comprometida | — | — |
| V4 | ✗ Comprometida | — | — |
| V5 | — | — | ✗ En riesgo |
| V6 | ✗ En riesgo | — | — |
| V7 | — | — | — |
| V8 | ✗ En riesgo | — | — |

---

## V1 — Backend /inv-api sin Autenticación (CVSS 9.9)

**Categoría OWASP:** A01 Broken Access Control + A07 Identification and Authentication Failures  
**Estado:** Explotada con evidencia real  

### Descripción
El backend `/inv-api` expone más de 76 endpoints completamente sin autenticación. Cualquier persona en internet puede ejecutar operaciones CRUD completas (leer, crear, modificar, eliminar) sin credenciales.

### Cómo se descubrió
1. Katana descubrió `/inv-api/openapi.json` durante el crawling de la aplicación
2. El archivo documentó 87 endpoints sin campo `security` — ninguno requiere token
3. Inspección del bundle JS confirmó que `/inv-api` es el único backend sin controles de acceso

### Evidencia de explotación

**Enumeración de productos:**
```bash
curl -s "https://wo.dieselsoft.co/inv-api/api/product/products?branch_id=ViJKnOKl4KbDfgeR9cdb"
```
→ **554 productos** con nombre, precio, cantidad, stock, código y ubicación física

**Extracción de ventas:**
```
https://wo.dieselsoft.co/inv-api/api/sale/
```
→ **167 registros** con nombres, cédulas de identidad y teléfonos de clientes y empleados

**Acceso a órdenes de trabajo:**
```
https://wo.dieselsoft.co/inv-api/api/work-orders/
```
→ **50 órdenes** con nombres de clientes, matrículas y números de chasis de vehículos

**Inserción de datos falsos:**
```bash
curl -s -X POST "https://wo.dieselsoft.co/inv-api/api/category/register" \
  -H "Content-Type: application/json" \
  -d '{"name":"PRUEBA SEGURIDAD"}'
```
→ Categoría creada exitosamente: `{"category_id":"h0uXP3yUcsIMdPHWq15F"}`

---

## V2 — PDFs con URLs Permanentes (CVSS 8.1)

**Categoría OWASP:** A01 Broken Access Control + A02 Cryptographic Failures  
**Estado:** Explotada

### Descripción
Las respuestas del endpoint de órdenes de trabajo incluyen URLs de Firebase Storage con parámetro `Expires=16447032000`, que corresponde al **año 2491**. Cualquier persona puede acceder a estos documentos permanentemente sin autenticación.

### Evidencia
```bash
curl -s "https://wo.dieselsoft.co/inv-api/api/work-orders/" | grep "urlFile"
# Campo urlFile: URL de Google Cloud Storage con Expires=16447032000
# Año de expiración: 2491
```

Los PDFs contienen información comercial confidencial: servicios prestados, datos del vehículo, firma del cliente.

---

## V3 — Credenciales Firebase Expuestas (CVSS 7.5)

**Categoría OWASP:** A02 Cryptographic Failures  
**Estado:** Verificada

### Descripción
El bundle JavaScript público contiene la configuración completa de Firebase en texto plano. Cualquier persona puede descargar el archivo y obtener las credenciales del proyecto.

### Credenciales encontradas
```
Archivo: https://wo.dieselsoft.co/assets/index-BMwkIzXx.js
Búsqueda: Ctrl+F → "apiKey"

apiKey:            "AIzaSyCG_Y4Heup1vPRYOYfXeN8OL7lF-T91wB4"
authDomain:        "w-o-ds.firebaseapp.com"
projectId:         "w-o-ds"
storageBucket:     "w-o-ds.firebasestorage.app"
messagingSenderId: "317020473872"
appId:             "1:317020473872:web:72d4a039736fe3350e5895"
```

---

## V4 — Firebase Storage Público (CVSS 7.5)

**Categoría OWASP:** A02 Cryptographic Failures  
**Estado:** Explotada

### Descripción
Las reglas de Firebase Storage permiten lectura pública (`allow read: if true`). Con las URLs de V2 y las credenciales de V3, cualquier persona puede descargar todos los archivos del bucket sin autenticación.

### Evidencia
Se accedió directamente desde el navegador a URLs de Firebase Storage obtenidas de las respuestas de la API. Imágenes y PDFs descargados sin credenciales.

---

## V5 — Sin Rate Limiting (CVSS 7.5)

**Categoría OWASP:** A04 Insecure Design  
**Estado:** Verificada

### Descripción
Ningún endpoint implementa control de tasa de solicitudes. Un atacante puede enviar miles de peticiones por segundo habilitando ataques de denegación de servicio y exfiltración automatizada masiva.

### Evidencia
```bash
for i in {1..20}; do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" \
    "https://wo.dieselsoft.co/inv-api/api/category/" \
    -H "User-Agent: Mozilla/5.0"
done
# Resultado: Request 1: 200 ... Request 20: 200
# Ningún bloqueo ni advertencia en 20 solicitudes consecutivas
```

---

## V6 — TLS 1.0 y 1.1 Activos (CVSS 6.5)

**Categoría OWASP:** A02 Cryptographic Failures  
**Estado:** Verificada

### Descripción
El servidor acepta TLS 1.0 y TLS 1.1, deprecados en 2020 mediante RFC 8996. Un atacante con acceso a la red puede forzar una negociación a la baja (downgrade attack) para explotar vulnerabilidades conocidas como POODLE.

### Evidencia
```bash
openssl s_client -connect wo.dieselsoft.co:443 -tls1 < /dev/null 2>&1 | grep Protocol
# Protocol: TLSv1 ← ACEPTADO

openssl s_client -connect wo.dieselsoft.co:443 -tls1_1 < /dev/null 2>&1 | grep Protocol
# Protocol: TLSv1.1 ← ACEPTADO
```

---

## V7 — Headers HTTP Faltantes (CVSS 5.3)

**Categoría OWASP:** A05 Security Misconfiguration  
**Estado:** Verificada

### Descripción
El servidor no implementa ninguno de los 5 headers de seguridad HTTP estándar recomendados por OWASP.

### Evidencia
```bash
curl -s -I "https://wo.dieselsoft.co/" -H "User-Agent: Mozilla/5.0"
```

| Header | Presente | Riesgo sin él |
|---|---|---|
| Strict-Transport-Security | ✗ No | No obliga HTTPS al navegador |
| X-Frame-Options | ✗ No | Clickjacking mediante iframes |
| X-Content-Type-Options | ✗ No | MIME sniffing |
| Content-Security-Policy | ✗ No | Cross-Site Scripting (XSS) |
| Permissions-Policy | ✗ No | Acceso a cámara/micrófono/geolocalización |

---

## V8 — Debug/Swagger en Producción (CVSS 5.3)

**Categoría OWASP:** A05 Security Misconfiguration + A09 Logging Failures  
**Estado:** Verificada

### Descripción
Los endpoints de debug y documentación están activos en el entorno de producción, entregando a cualquier atacante el mapa completo de la API.

### Evidencia
```bash
# Swagger UI — mapa completo de la API sin autenticación
curl -s -o /dev/null -w "%{http_code}" https://wo.dieselsoft.co/inv-api/docs
# 200

# ReDoc — documentación alternativa
curl -s -o /dev/null -w "%{http_code}" https://wo.dieselsoft.co/inv-api/redoc
# 200

# Endpoint de debug activo
curl -s -I "https://wo.dieselsoft.co/inv-api/api/sale/debug-register" -X POST
# HTTP/2 200
```

---

## Mitigaciones

### Mitigación 1 — JWT + RBAC (resuelve V1)

**Estándar:** OWASP A01 · NIST AC-3 · ISO 27002 9.4  
**Esfuerzo:** 2–3 días de desarrollo

```python
# FastAPI — Middleware JWT global
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
import jwt

security = HTTPBearer()

async def verify_token(token = Depends(security)):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

# RBAC — solo ADMIN puede ejecutar DELETE
async def require_admin(payload = Depends(verify_token)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Requiere rol administrador")
    return payload

# Aplicar a todos los endpoints
@app.get("/api/product/products", dependencies=[Depends(verify_token)])
async def get_products():
    ...

@app.delete("/api/product/{id}", dependencies=[Depends(require_admin)])
async def delete_product(id: str):
    ...
```

**Flujo:**
```
Solicitud → Middleware JWT → ¿Token válido?
                                ├── NO  → HTTP 401
                                └── SÍ → ¿Requiere ADMIN?
                                              ├── NO  → Endpoint → Respuesta
                                              └── SÍ → ¿Es ADMIN?
                                                            ├── NO  → HTTP 403
                                                            └── SÍ → Endpoint → Respuesta
```

---

### Mitigación 2 — Firebase: URLs Firmadas + Credenciales + Storage (resuelve V2, V3, V4)

**Estándar:** OWASP A02 · NIST SC-28  
**Esfuerzo:** 3–4 días

```javascript
// V2: Signed URLs con expiración 30 minutos
const [url] = await storage.bucket(BUCKET).file(fileName).getSignedUrl({
  action: 'read',
  expires: Date.now() + 30 * 60 * 1000  // 30 minutos
});

// V3: Pasos en Firebase Console
// 1. Project Settings → API Keys → Revocar key comprometida
// 2. Generar nueva key
// 3. Agregar restricción: solo wo.dieselsoft.co

// V4: Firebase Storage Rules
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if request.auth != null;
    }
  }
}
```

---

### Mitigación 3 — Rate Limiting (resuelve V5)

**Estándar:** OWASP A04 · NIST SI-10  
**Esfuerzo:** 0.5 días

```nginx
# nginx.conf
http {
    limit_req_zone $binary_remote_addr zone=api_general:10m rate=100r/15m;
    limit_req_zone $binary_remote_addr zone=api_delete:10m  rate=10r/1h;

    server {
        location /inv-api/ {
            limit_req zone=api_general burst=20 nodelay;
            limit_req_status 429;
        }

        location ~* /inv-api/.*DELETE {
            limit_req zone=api_delete burst=2 nodelay;
            limit_req_status 429;
        }
    }
}
```

---

### Mitigación 4 — Deshabilitar TLS 1.0 y 1.1 (resuelve V6)

**Estándar:** OWASP A02 · RFC 8996 · NIST SC-8  
**Esfuerzo:** 1 hora

```nginx
# nginx.conf
server {
    ssl_protocols TLSv1.2 TLSv1.3;       # Solo versiones seguras
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
}
```

**Verificación post-implementación:**
```bash
openssl s_client -connect wo.dieselsoft.co:443 -tls1 < /dev/null 2>&1 | grep Protocol
# Esperado: Connection refused / handshake failure ← CORREGIDO
```

---

### Mitigación 5 — Headers de Seguridad HTTP (resuelve V7)

**Estándar:** OWASP A05 · NIST SI-10  
**Esfuerzo:** 2 horas

```nginx
# nginx.conf
server {
    add_header Strict-Transport-Security  "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options            "DENY" always;
    add_header X-Content-Type-Options     "nosniff" always;
    add_header Content-Security-Policy    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" always;
    add_header Permissions-Policy         "camera=(), microphone=(), geolocation=()" always;
}
```

**Verificación post-implementación:**
```bash
curl -s -I "https://wo.dieselsoft.co/" | grep -E "Strict|X-Frame|X-Content|Content-Security|Permissions"
# Esperado: los 5 headers presentes ← CORREGIDO
```

---

### Mitigación 6 — Deshabilitar Debug/Swagger en Producción (resuelve V8)

**Estándar:** OWASP A05 · NIST CM-7  
**Esfuerzo:** 1 hora

```python
# FastAPI — condicional por entorno
import os

ENV = os.getenv("NODE_ENV", "development")

app = FastAPI(
    docs_url  = "/docs"  if ENV != "production" else None,
    redoc_url = "/redoc" if ENV != "production" else None,
)

# Endpoint debug solo en desarrollo
if ENV != "production":
    @app.post("/api/sale/debug-register")
    async def debug_register():
        ...
```

**Verificación post-implementación:**
```bash
curl -s -o /dev/null -w "%{http_code}" https://wo.dieselsoft.co/inv-api/docs
# Esperado: 404 ← CORREGIDO
```

---

## Plan de Implementación

| Prioridad | Vulnerabilidades | CVSS | Esfuerzo | Descripción |
|---|---|---|---|---|
| **P1 · Inmediata** | V1 | 9.9 | 2–3 días | Middleware JWT global en FastAPI + RBAC para DELETE |
| **P2 · Corto plazo** | V2, V3, V4, V5 | 7.5–8.1 | 4 días | Firebase (reglas + Signed URLs + revocar key) + Rate limiting nginx |
| **P3 · Mediano plazo** | V6, V7, V8 | 5.3–6.5 | 2 días | nginx: TLS + Headers + NODE_ENV para debug |
| **TOTAL** | **V1–V8** | — | **~9 días** | **100% de vulnerabilidades eliminadas** |

### Reducción de riesgo por fase

```
Antes de mitigaciones:    CVSS máximo 9.9  ████████████████████ 100% exposición
Después de P1 (JWT):      CVSS máximo 8.1  ████████░░░░░░░░░░░░  41% exposición
Después de P2 (Firebase): CVSS máximo 6.5  ██████░░░░░░░░░░░░░░  15% exposición
Después de P3 (nginx):    CVSS máximo 0.0  ░░░░░░░░░░░░░░░░░░░░   0% exposición
```

---

## Referencias Técnicas

| Estándar | URL |
|---|---|
| OWASP Top 10 (2021) | https://owasp.org/Top10/2021/ |
| OWASP Testing Guide v4.2 | https://owasp.org/www-project-web-security-testing-guide/v42/ |
| NIST SP 800-53 Rev. 5 | https://doi.org/10.6028/NIST.SP.800-53r5 |
| CVSS v3.1 Specification | https://www.first.org/cvss/v3.1/specification-document |
| RFC 8996 — Deprecating TLS 1.0/1.1 | https://www.rfc-editor.org/rfc/rfc8996 |
| RFC 7519 — JWT | https://www.rfc-editor.org/rfc/rfc7519 |
| Firebase Security Rules | https://firebase.google.com/docs/storage/security |
| OpenAPI Specification v3.1.0 | https://spec.openapis.org/oas/v3.1.0 |

---

*Documento parte del repositorio: Análisis de Vulnerabilidades — Diesel Soft SRL · 2026*  
*Rimer Saul Rosa Herrera — Diplomado en Ciberseguridad, EUPG-UMSS*
