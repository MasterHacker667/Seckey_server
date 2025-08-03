# 📘 Documentación Técnica – Proyecto FirmaApp v1.0-alpha

## 🧾 Descripción General

**FirmaApp** es una aplicación diseñada como prototipo funcional (versión 1.0-alpha) para un sistema de firma de archivos y manejo seguro de datos. Este sistema incluye dos componentes principales:

1. **Un servidor Rust (`adminServer`)** para operaciones criptográficas, incluyendo firma digital.
2. **Una API REST en Python con FastAPI (`apiAdicional`)** para exponer los servicios de forma accesible vía HTTP.

Esta versión está empaquetada completamente dentro de una imagen de Docker multiplataforma y autocontenida.

## ⚙️ Arquitectura del Proyecto

La imagen Docker contiene:

```
/
├── app/
│   ├── adminServer/              # Binario Rust compilado
│   │   └── target/release/adminServer
│   └── apiAdicional/            # Código fuente de la API Python
│       ├── main.py
│       └── ...
├── imagenDefault.jpg            # Imagen requerida por el sistema (visible en /root o /app según uso)
```

## 🛠️ Funcionalidades Actuales

### 🔒 Componente Rust (`adminServer`)
- Compilado con `cargo build --release`.
- Incluye operaciones criptográficas con dependencia de `openssl`.
- Utiliza una imagen (`imagenDefault.jpg`) que es cargada o manipulada por el binario.
- Ejecutable a través de un alias como:
  ```bash
  alias seckey="./app/adminServer/target/release/adminServer"
  ```

### 🌐 Componente Python (`apiAdicional`)
- Servidor FastAPI que:
  - Expone endpoints HTTP.
  - Puede comunicarse con el binario Rust.
  - Puede manipular firmas, recibir peticiones desde frontend u otras aplicaciones.

## 🧰 Dependencias

### En Rust:
- `openssl-sys` requiere `libssl-dev` y `pkg-config` para compilar correctamente.
- Cargo build se realiza en una etapa separada del Dockerfile.

### En Python:
- `python3-fastapi`
- `python3-uvicorn`
- `python3-cryptography`

## 🐳 Dockerfile - Multietapa

1. **Etapa 1: Builder de Rust**
   - Imagen base: `rust:1.88`
   - Instala `libssl-dev`, `pkg-config`, y compila en modo `--release`.

2. **Etapa 2: Python base**
   - Imagen: `python:3.11.2-slim`
   - Instala dependencias vía `apt`.

3. **Etapa final: Producción**
   - Imagen base: `debian:bookworm-slim`
   - Copia binario Rust ya compilado y la API Python.
   - Expone el puerto `8000`.
   - Comando por defecto:
     ```bash
     python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
     ```

## 🚀 Ejecución

Desde Docker:
```bash
docker build -t firmaapp .
docker run -it -p 8000:8000 firmaapp
```

Desde el contenedor:
```bash
alias seckey="./app/adminServer/target/release/adminServer"
seckey
```

## 📂 Notas adicionales

- `imagenDefault.jpg` debe existir y estar disponible al binario.
- La clave secreta se genera o usa al ejecutar el binario Rust.
- Esta versión es un MVP (Producto Mínimo Viable) para pruebas internas.
- Futuras versiones incorporarán microservicios, cifrado AES, autenticación, comunicación segura, etc.
