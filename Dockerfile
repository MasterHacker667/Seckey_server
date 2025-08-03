# Etapa 1: Build Rust
FROM rust:1.88 as builder

# Instalar dependencias necesarias para compilar openssl-sys
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    build-essential \
    ca-certificates \
    curl

# Crear carpeta oculta para el proyecto Rust
WORKDIR /opt/.hidden_adminServer

# Copiar proyecto Rust y la imagen
COPY adminServer/ .
COPY imagenDefault.jpg .

# Compilar en modo release
RUN cargo build --release

# Etapa 2: Base Python + librerías FastAPI vía apt
FROM python:3.11.2-slim as python-base

RUN apt-get update && apt-get install -y \
    python3-fastapi \
    python3-uvicorn \
    python3-cryptography \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/apiAdicional
COPY apiAdicional/ .

# Etapa final: Imagen con Rust ejecutable + Python
FROM debian:bookworm-slim

# Instalar dependencias necesarias para ejecutar binarios Rust y la API
RUN apt-get update && apt-get install -y \
    python3 \
    python3-fastapi \
    python3-uvicorn \
    python3-cryptography \
    libssl-dev \
    pkg-config \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Carpeta de trabajo
WORKDIR /app

# Copiar adminServer compilado y la imagen
COPY --from=builder /opt/.hidden_adminServer ./adminServer

# Copiar apiAdicional
COPY --from=python-base /app/apiAdicional ./apiAdicional

# Copiar la imagen al home
COPY --from=builder /opt/.hidden_adminServer/imagenDefault.jpg /root/imagenDefault.jpg

# Exponer puerto de la API
EXPOSE 8000

# Comando principal
WORKDIR /app/apiAdicional

RUN echo "alias seckey='/app/adminServer/target/release/adminServer'" >> /root/.bashrc

CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
