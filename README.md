# Análisis de Vulnerabilidades — Aplicación Web Órdenes de Trabajo
## Diesel Soft SRL · Basado en OWASP Top 10

**Autor:** Rimer Saul Rosa Herrera  
**Institución:** Universidad Mayor de San Simón (UMSS) — EUPG, FCT  
**Programa:** Diplomado en Ciberseguridad  
**Fecha:** Julio 2026  
**Dominio analizado:** `wo.dieselsoft.co`  

---

## Resumen

Análisis dinámico de seguridad (DAST) sobre la aplicación web de Órdenes de Trabajo de Diesel Soft SRL, ejecutado con **autorización explícita de la empresa** desde el dominio público `wo.dieselsoft.co`. Se identificaron **8 vulnerabilidades activas** — 5 explotadas con evidencia real — siendo la más crítica la ausencia total de autenticación en el backend `/inv-api` (CVSS 9.9). Se proponen 6 mitigaciones técnicas que eliminan el 100% de los riesgos en aproximadamente 9 días de desarrollo.

---

## Datos Generales

| Parámetro | Valor |
|---|---|
| Sistema operativo | Kali Linux |
| Objetivo | `https://wo.dieselsoft.co` |
| IP del servidor | `159.89.139.254` |
| Tipo de análisis | Caja Gris (Gray Box) · DAST |
| Marco de referencia | OWASP Top 10 (2021) · OWASP Testing Guide v4.2 |
| Clasificación de severidad | CVSS v3.1 |
| Autorización | Explícita — Diesel Soft SRL |
| Stack tecnológico | React · nginx · FastAPI/Python · Firebase |

---

## Estructura del Repositorio

```
📁 analisis-vulnerabilidades-dieselsoft/
├── README.md              ← Este archivo (portada general)
├── HERRAMIENTAS.md        ← Herramientas utilizadas, instalación y parámetros
├── PROCESO.md             ← 5 fases del análisis con comandos exactos
├── RESULTADOS.md          ← Vulnerabilidades, explotaciones y mitigaciones
└── evidencias/
    ├── fase1_reconocimiento/
    ├── fase2_enumeracion/
    ├── fase3_identificacion/
    └── fase4_explotacion/
```

---

## Resultados en Síntesis

| ID | Vulnerabilidad | CVSS | Severidad |
|---|---|---|---|
| V1 | Backend /inv-api sin autenticación (76+ endpoints) | **9.9** | 🔴 CRÍTICA |
| V2 | PDFs con URLs permanentes (año 2491) | **8.1** | 🟠 ALTA |
| V3 | Credenciales Firebase en código fuente público | **7.5** | 🟠 ALTA |
| V4 | Firebase Storage accesible sin autenticación | **7.5** | 🟠 ALTA |
| V5 | Ausencia de rate limiting (riesgo DoS) | **7.5** | 🟠 ALTA |
| V6 | TLS 1.0 y TLS 1.1 deprecados activos | **6.5** | 🟡 MEDIA |
| V7 | Headers de seguridad HTTP faltantes | **5.3** | 🟡 MEDIA |
| V8 | Debug/Swagger activos en producción | **5.3** | 🟡 MEDIA |

---

## Documentación Completa

- 📄 [HERRAMIENTAS.md](./HERRAMIENTAS.md) — herramientas, instalación y parámetros usados
- 📄 [PROCESO.md](./PROCESO.md) — 5 fases del análisis con todos los comandos
- 📄 [RESULTADOS.md](./RESULTADOS.md) — vulnerabilidades, explotaciones y mitigaciones

---

## Declaración Ética

Este análisis fue realizado con **autorización explícita de Diesel Soft SRL** en el marco del Diplomado en Ciberseguridad de la EUPG-UMSS. Todas las pruebas se ejecutaron sin causar daño operativo permanente. Los datos personales obtenidos fueron tratados con confidencialidad. El registro de prueba ("PRUEBA SEGURIDAD") insertado fue comunicado a la empresa para su eliminación.

---

*Cochabamba, Bolivia · Julio 2026 · Rimer Saul Rosa Herrera*
