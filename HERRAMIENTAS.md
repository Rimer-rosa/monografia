# HERRAMIENTAS.md
## Herramientas Utilizadas en el Análisis de Seguridad

**Proyecto:** Análisis de Vulnerabilidades — Diesel Soft SRL  
**Sistema base:** Kali Linux  
**Tipo de análisis:** DAST · Caja Gris

---

## Índice

1. [Resumen de herramientas](#resumen)
2. [curl](#1-curl)
3. [Katana](#2-katana)
4. [Gobuster](#3-gobuster)
5. [Wappalyzer](#4-wappalyzer)
6. [openssl](#5-openssl)
7. [Python 3](#6-python-3)
8. [Postman](#7-postman)
9. [ZAP](#8-zap-owasp-zed-attack-proxy)
10. [nmap](#9-nmap)
11. [Navegador web](#10-navegador-web--devtools)

---

## Resumen

| # | Herramienta | Fase | Uso principal |
|---|---|---|---|
| 1 | **curl** | 1, 3, 4 | Solicitudes HTTP, verificación de headers, explotación |
| 2 | **Katana** | 2 | Crawling de URLs y análisis de JavaScript |
| 3 | **Gobuster** | 2 | Fuzzing de directorios y rutas ocultas |
| 4 | **Wappalyzer** | 1 | Identificación de stack tecnológico |
| 5 | **openssl** | 3 | Verificación de protocolos TLS/SSL |
| 6 | **Python 3** | 4 | Scripting y automatización |
| 7 | **Postman** | 3, 4 | Exploración visual de endpoints |
| 8 | **ZAP** | 3 | Scanner automático de vulnerabilidades |
| 9 | **nmap** | 1 | Escaneo de puertos y servicios |
| 10 | **Navegador + DevTools** | 1, 2, 4 | Inspección de JS, Wappalyzer, acceso manual |

---

## 1. curl

**Descripción:** Cliente HTTP de línea de comandos para transferencia de datos a través de URLs. Permite construir solicitudes HTTP/HTTPS personalizadas con headers, métodos y cuerpos arbitrarios.

**Por qué se usó:** Es nativo en Kali Linux, no requiere instalación, y permite verificar endpoints directamente sin interfaz gráfica. Ideal para reproducir ataques de forma precisa y documentable.

**Instalación:**
```bash
# Nativo en Kali Linux — no requiere instalación
curl --version
```

**Parámetros utilizados en este análisis:**

| Parámetro | Descripción | Ejemplo |
|---|---|---|
| `-s` | Silent: oculta barra de progreso | `curl -s "https://..."` |
| `-I` | Solo headers (HEAD request) | `curl -s -I "https://..."` |
| `-v` | Verbose: muestra todo el intercambio | `curl -v "https://..."` |
| `-X` | Especifica el método HTTP | `-X POST` |
| `-H` | Agrega un header personalizado | `-H "Content-Type: application/json"` |
| `-d` | Cuerpo de la solicitud (data) | `-d '{"name":"test"}'` |
| `-o` | Guarda la respuesta en archivo | `-o /dev/null` |
| `-w` | Formato de salida personalizado | `-w "%{http_code}"` |

---

## 2. Katana

**Descripción:** Herramienta de crawling y enumeración de URLs desarrollada por ProjectDiscovery. Analiza HTML y ejecuta JavaScript dinámicamente para descubrir rutas generadas por frameworks como React.

**Por qué se usó:** La aplicación Órdenes de Trabajo es una SPA (Single Page Application) en React. Las rutas no están en el HTML estático sino en el bundle JavaScript. Katana ejecuta el JS y extrae las URLs dinámicas que otras herramientas no ven.

**Instalación:**
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

**Parámetros utilizados en este análisis:**

| Parámetro | Valor | Descripción |
|---|---|---|
| `-u` | `https://wo.dieselsoft.co` | URL objetivo |
| `-d` | `3` | Profundidad máxima de rastreo (niveles) |
| `-jc` | — | JavaScript crawling: ejecuta JS para encontrar URLs dinámicas |
| `-timeout` | `10` | Tiempo máximo por solicitud en segundos |
| `-rate-limit` | `100` | Máximo de solicitudes por segundo |

**Comando usado:**
```bash
katana -u https://wo.dieselsoft.co -d 3 -jc -timeout 10 -rate-limit 100
```

---

## 3. Gobuster

**Descripción:** Herramienta de fuzzing de directorios, archivos y subdominios escrita en Go. Prueba sistemáticamente miles de rutas contra un servidor web usando wordlists.

**Por qué se usó:** Después de identificar el backend `/inv-api` con Katana, Gobuster confirmó qué rutas existían dentro de ese backend usando un diccionario de 220,558 palabras.

**Instalación:**
```bash
# Nativo en Kali Linux
gobuster version

# Si no está instalado:
apt install gobuster -y
```

**Parámetros utilizados en este análisis:**

| Parámetro | Valor | Descripción |
|---|---|---|
| `dir` | — | Modo fuzzing de directorios |
| `-u` | `https://wo.dieselsoft.co/inv-api` | URL objetivo |
| `-w` | `directory-list-2.3-medium.txt` | Wordlist con 220,558 rutas |
| `-t` | `50` | 50 hilos concurrentes |
| `--exclude-length` | `1223,1070` | Excluir respuestas de esas longitudes (páginas de error genéricas) |

**Comando usado:**
```bash
gobuster dir \
  -u https://wo.dieselsoft.co/inv-api \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 50 \
  --exclude-length 1223,1070
```

> **Nota:** Si el wordlist no existe en esa ruta, verificar con: `ls /usr/share/wordlists/dirbuster/`

---

## 4. Wappalyzer

**Descripción:** Extensión de navegador que identifica tecnologías usadas en sitios web mediante análisis de headers HTTP, código HTML y archivos JavaScript.

**Por qué se usó:** `whatweb` fue bloqueado por Cloudflare con error 530. Wappalyzer opera desde el navegador y Cloudflare no lo bloqueó al ser tráfico legítimo de usuario.

**Instalación:**
```
Extensión para Chrome/Firefox:
https://www.wappalyzer.com/apps/
```

**Uso en este análisis:**
- Navegar a `https://wo.dieselsoft.co/login`
- Hacer clic en el ícono de Wappalyzer en la barra del navegador
- Leer las tecnologías detectadas

**Resultado obtenido:**

| Tecnología | Categoría |
|---|---|
| React | Framework JavaScript |
| React Router | Enrutamiento SPA |
| Tailwind CSS | Framework CSS |
| nginx | Servidor web |

---

## 5. openssl

**Descripción:** Herramienta criptográfica de línea de comandos que implementa SSL/TLS. Permite inspeccionar certificados digitales y verificar qué versiones de protocolo acepta un servidor.

**Por qué se usó:** Para verificar si el servidor aceptaba protocolos TLS deprecados (TLS 1.0 y TLS 1.1) que podrían ser explotados mediante ataques de negociación a la baja.

**Instalación:**
```bash
# Nativo en Kali Linux
openssl version
```

**Parámetros utilizados en este análisis:**

| Parámetro | Descripción |
|---|---|
| `s_client` | Modo cliente SSL/TLS |
| `-connect` | Host:puerto objetivo |
| `-tls1` | Forzar uso de TLS 1.0 |
| `-tls1_1` | Forzar uso de TLS 1.1 |
| `< /dev/null` | Cierra la conexión inmediatamente después de establecerla |

**Comandos usados:**
```bash
# Verificar TLS 1.0
openssl s_client -connect wo.dieselsoft.co:443 -tls1 < /dev/null 2>&1 | grep Protocol

# Verificar TLS 1.1
openssl s_client -connect wo.dieselsoft.co:443 -tls1_1 < /dev/null 2>&1 | grep Protocol

# Verificar certificado SSL
curl -v https://wo.dieselsoft.co/ 2>&1 | grep -A 10 "* Server certificate"
```

---

## 6. Python 3

**Descripción:** Lenguaje de programación interpretado usado para automatización, scripting y procesamiento de datos en el análisis de seguridad.

**Por qué se usó:** Para automatizar solicitudes repetitivas, procesar respuestas JSON de la API y generar scripts personalizados de verificación.

**Instalación:**
```bash
# Nativo en Kali Linux
python3 --version

# Librería requests si no está
pip3 install requests
```

**Uso en este análisis:**
```python
import requests

# Ejemplo: enumerar endpoints sin autenticación
base = "https://wo.dieselsoft.co/inv-api"
endpoints = ["/api/product/products", "/api/sale/", "/api/work-orders/"]

for ep in endpoints:
    r = requests.get(base + ep, params={"branch_id": "ViJKnOKl4KbDfgeR9cdb"})
    print(f"{ep}: HTTP {r.status_code} — {len(r.json())} registros")
```

---

## 7. Postman

**Descripción:** Cliente HTTP visual con interfaz gráfica para explorar, probar y documentar APIs REST.

**Por qué se usó:** Para explorar endpoints del openapi.json de forma visual, organizar las solicitudes por colecciones y verificar respuestas con formato JSON legible.

**Instalación:**
```bash
# Descargar desde:
# https://www.postman.com/downloads/

# En Kali Linux:
snap install postman
```

**Uso en este análisis:** Importar el archivo `openapi.json` directamente en Postman para generar automáticamente la colección completa de endpoints:
```
File → Import → Link → https://wo.dieselsoft.co/inv-api/openapi.json
```

---

## 8. ZAP (OWASP Zed Attack Proxy)

**Descripción:** Scanner de vulnerabilidades web de código abierto desarrollado por OWASP. Actúa como proxy interceptor que captura y analiza el tráfico HTTP/HTTPS.

**Por qué se usó:** Para ejecutar un escaneo automático de vulnerabilidades sobre los endpoints identificados y verificar headers de seguridad de forma sistemática.

**Instalación:**
```bash
# En Kali Linux
apt install zaproxy -y

# O descargar desde:
# https://www.zaproxy.org/download/
```

**Uso en este análisis:** Escaneo activo sobre `https://wo.dieselsoft.co` con configuración de spider + active scan para detectar vulnerabilidades automáticamente.

---

## 9. nmap

**Descripción:** Herramienta de escaneo de redes y puertos. Detecta hosts activos, puertos abiertos, servicios en ejecución y versiones de software.

**Por qué se usó:** Para verificar qué puertos y servicios estaban activos en la IP del servidor (`159.89.139.254`).

**Instalación:**
```bash
# Nativo en Kali Linux
nmap --version
```

**Comando usado:**
```bash
nmap -sV -p 80,443,8080,8443 159.89.139.254
```

---

## 10. Navegador Web + DevTools

**Descripción:** Navegador web (Chrome/Firefox) con herramientas de desarrollo integradas para inspeccionar código fuente, tráfico de red y JavaScript.

**Por qué se usó:** Para inspeccionar manualmente el bundle JavaScript y encontrar las constantes de backend (`/api`, `/inv-api`, `/auth-api`) y las credenciales de Firebase hardcodeadas.

**Uso en este análisis:**

```
1. Abrir https://wo.dieselsoft.co
2. DevTools → Sources → assets/index-BMwkIzXx.js
3. Ctrl+F → buscar "apiKey" → credenciales Firebase encontradas
4. Ctrl+F → buscar "/inv-api" → backends identificados
5. Ctrl+F → buscar "fetch(" → uso de los backends confirmado
```

---

*Documento parte del repositorio: Análisis de Vulnerabilidades — Diesel Soft SRL · 2026*
