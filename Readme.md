# 🖼️ Proyecto Rust - Prototipo de Seguridad y Procesamiento de Imágenes

Este prototipo desarrollado en Rust tiene como objetivo:

- Subir imágenes desde una ruta local.
- Verificar su existencia y copiarlas a una ruta predeterminada.
- Leer su contenido binario y mezclarlo con frases generadas dinámicamente.
- Codificar el resultado con Base64, SHA-256 o SHA-512.
- Almacenar la salida como archivos `.love`.
- Comprimir y descomprimir archivos con ZIP.
- Proteger entradas de usuario como contraseñas con entrada oculta.

---

## 🛠️ Tecnologías y librerías utilizadas

- **Rust** (versión estable)
- [`base64`](https://crates.io/crates/base64)
- [`chrono`](https://crates.io/crates/chrono)
- [`openssl`](https://crates.io/crates/openssl)
- [`rand`](https://crates.io/crates/rand)
- [`rpassword`](https://crates.io/crates/rpassword)
- [`sha2`](https://crates.io/crates/sha2)
- [`zip`](https://crates.io/crates/zip)
- [`walkdir`](https://crates.io/crates/walkdir)

---

## 📁 Estructura del Proyecto

/src
└── main.rs # Lógica principal del prototipo
/images/
└── imagenDefault.jpg # Imagen copiada desde ruta de origen
/Server/Credentials/
└── Patricia.love # Archivo generado y cifrado
└── Patricia.zip # Archivo comprimido opcionalmente


---

## 🚀 Cómo usarlo

1. **Clona el proyecto:**

   ```bash
   git clone https://github.com/tu_usuario/tu_repo.git
   cd tu_repo

## Dependencias necesarias
cargo add base64 chrono openssl --features vendored
cargo add rand rpassword sha2 walkdir zip

## NOTAS
El software ya trae por defecto una imagen para empezar el cifrado, pero mas adelante se pide subir otra.

## ESTE SOFTWARE SOLO FUNCIONA EN GNU/LINUX!!!!!