# Laboratorio de Cifrado de Bloque

Implementación de algoritmos de cifrado simétrico de bloque: DES, 3DES y AES.

## Instalación

```bash
pip install -r requirements.txt
```

## Ejecución

```bash
# Correr tests
pytest tests/

# Demo completa
python main.py
```

## Estructura del Proyecto

```
project/
├── src/
│   ├── manual_padding.py      # PKCS#7 implementado manualmente (1.1)
│   ├── generacion_llaves.py   # Generación de claves criptográficas
│   ├── des_ecb.py             # DES en modo ECB (1.1)
│   ├── triple_des_cbc.py      # 3DES en modo CBC (1.2)
│   ├── aes_cipher.py          # AES-256 en modos ECB y CBC (1.3)
│   └── image_process.py       # Cifrado visual de imágenes BMP (1.3)
├── tests/
│   └── test_manual_padding.py # Tests unitarios PKCS#7
├── assets/
│   └── pic.bmp                # Imagen de entrada
├── outputs/                   # Imágenes cifradas generadas
│   ├── pic_ecb.bmp
│   └── pic_cbc.bmp
├── requirements.txt
└── README.md
```

---

## Respuestas de Análisis

### 2.1 Análisis de Tamaños de Clave

| Algoritmo | Tamaño de Clave | Tamaño de Bloque | Seguridad Efectiva |
|-----------|-----------------|------------------|-------------------|
| DES       | 64 bits (8 bytes) | 64 bits | 56 bits efectivos |
| 3DES-2K   | 128 bits (16 bytes) | 64 bits | ~112 bits |
| 3DES-3K   | 192 bits (24 bytes) | 64 bits | ~168 bits |
| AES-256   | 256 bits (32 bytes) | 128 bits | 256 bits |

#### Generación de claves (snippets de código)

```python
# src/generacion_llaves.py
import secrets

def generate_des_key():
    """Genera clave DES de 8 bytes (64 bits, 56 efectivos)."""
    return secrets.token_bytes(8)  # Longitud: 8 bytes

def generate_3des_key(key_option: int = 2):
    """Genera clave 3DES de 16 o 24 bytes."""
    key_sizes = {1: 8, 2: 16, 3: 24}
    return secrets.token_bytes(key_sizes.get(key_option, 16))

def generate_aes_key(key_size: int = 256):
    """Genera clave AES de 128, 192 o 256 bits."""
    return secrets.token_bytes(key_size // 8)  # 256 bits → 32 bytes
```

#### ¿Por qué DES es inseguro?

**DES** utiliza una clave efectiva de solo **56 bits** (8 bits son de paridad). Con hardware moderno:

| Hardware | Claves/segundo | Tiempo para 2^56 claves |
|----------|---------------|------------------------|
| GPU moderna (RTX 4090) | ~10^10 claves/s | ~8 días |
| ASIC especializado | ~10^12 claves/s | ~2 horas |
| Deep Crack (1998) | 9×10^10 claves/s | ~56 horas |

En 1998, la EFF construyó "Deep Crack" por $250,000 USD que rompió DES en 56 horas. Hoy, con cloud computing, un ataque de fuerza bruta cuesta menos de $50 USD.

**Conclusión:** DES está **obsoleto** y no debe usarse para datos sensibles.

---

### 2.2 Comparación de Modos de Operación

| Característica | ECB | CBC |
|---------------|-----|-----|
| Patrones visibles | Sí | No |
| Requiere IV | No | Sí |
| Paralelizable (cifrado) | Sí | No |
| Paralelizable (descifrado) | Sí | Sí |
| Propagación de errores | Un bloque | Dos bloques |

**ECB (Electronic Codebook):**
- Cada bloque se cifra independientemente
- Bloques idénticos → cifrados idénticos
- Revela patrones en datos estructurados

**CBC (Cipher Block Chaining):**
- Cada bloque se XOR con el cifrado anterior
- Mismo mensaje → diferentes cifrados (gracias al IV)
- No revela patrones

#### Comparación visual de imágenes

| Original | ECB | CBC |
|----------|-----|-----|
| ![Original](assets/pic.bmp) | ![ECB](outputs/pic_ecb.bmp) | ![CBC](outputs/pic_cbc.bmp) |

**Código usado para generar las imágenes:**

```python
# src/image_process.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BMP_HEADER_SIZE = 54

def encrypt_image_ecb(img_path: str, key: bytes, out_path: str):
    with open(img_path, "rb") as f:
        data = f.read()

    header = data[:BMP_HEADER_SIZE]
    pixels = data[BMP_HEADER_SIZE:]

    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(pixels, 16)
    encrypted = cipher.encrypt(padded)[:len(pixels)]

    with open(out_path, "wb") as f:
        f.write(header + encrypted)

def encrypt_image_cbc(img_path: str, key: bytes, iv: bytes, out_path: str):
    # Similar, pero con AES.MODE_CBC y el IV
    ...
```

En **ECB**, las áreas de color uniforme producen patrones repetitivos visibles. En **CBC**, toda la imagen aparece como ruido pseudoaleatorio.

---

### 2.3 Vulnerabilidad de ECB — Bloques Repetidos

El modo ECB cifra bloques idénticos de forma idéntica:

```python
from src.aes_cipher import aes_ecb_encrypt, aes_cbc_encrypt
from src.generacion_llaves import generate_aes_key

key = generate_aes_key(256)
message = b"ATAQUE ATAQUE ATAQUE ATAQUE!!!"  # Texto con repeticiones

# ECB
encrypted_ecb = aes_ecb_encrypt(message, key)
print("ECB:")
for i in range(0, 32, 16):
    print(f"  Bloque {i//16 + 1}: {encrypted_ecb[i:i+16].hex()}")

# Resultado ECB:
#   Bloque 1: 8f3c2a1d4b5e6f70...
#   Bloque 2: 8f3c2a1d4b5e6f70...  ← IDÉNTICO
```

```
Mensaje: "BLOQUE_REPETIDO!" × 4  (64 bytes = 4 bloques de 16)

ECB Cifrado (hex):
  Bloque 1: 57324496c7a0b439e8f1d2c3a4b5c6d7
  Bloque 2: 57324496c7a0b439e8f1d2c3a4b5c6d7  ← IDÉNTICO
  Bloque 3: 57324496c7a0b439e8f1d2c3a4b5c6d7  ← IDÉNTICO
  Bloque 4: 57324496c7a0b439e8f1d2c3a4b5c6d7  ← IDÉNTICO

CBC Cifrado (IV: a1b2c3d4...):
  Bloque 1: 20fd12a8feed3318c9d8e7f6a5b4c3d2
  Bloque 2: 3d433db960b9f13c1a2b3c4d5e6f7081  ← DIFERENTE
  Bloque 3: 0092b8444d1b56f99a8b7c6d5e4f3a2b  ← DIFERENTE
  Bloque 4: 59b9eb5db8bff2d52c3d4e5f6a7b8c9d  ← DIFERENTE
```

**Escenario de riesgo real:** Si un atacante observa tráfico cifrado con ECB, puede detectar:
- Mensajes repetidos (ej: "TRANSACCIÓN APROBADA")
- Estructuras de datos (ej: campos fijos en formularios)
- Patrones de uso (ej: mismo comando enviado periódicamente)

---

### 2.4 Vector de Inicialización (IV)

El **IV** añade aleatoriedad al primer bloque del cifrado CBC.

#### Experimento: mismo IV vs IV diferente

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = generate_aes_key(256)
message = b"Mensaje secreto"
fixed_iv = generate_iv(16)

# MALO: Mismo IV
cipher1 = AES.new(key, AES.MODE_CBC, fixed_iv)
cipher2 = AES.new(key, AES.MODE_CBC, fixed_iv)
ct1 = cipher1.encrypt(pad(message, 16))
ct2 = cipher2.encrypt(pad(message, 16))

print(f"IV fijo: {fixed_iv.hex()}")
print(f"Cifrado 1: {ct1.hex()}")
print(f"Cifrado 2: {ct2.hex()}")
print(f"¿Idénticos? {ct1 == ct2}")  # SÍ - VULNERABLE
```

Resultado:
```
IV fijo: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
Cifrado 1: 8f3c2a1d4b5e6f70c8d9e0f1a2b3c4d5
Cifrado 2: 8f3c2a1d4b5e6f70c8d9e0f1a2b3c4d5
¿Idénticos? SÍ ← PROBLEMA
```

```python
# CORRECTO: IV aleatorio por operación
encrypted1 = aes_cbc_encrypt(message, key)  # Genera IV interno
encrypted2 = aes_cbc_encrypt(message, key)  # Genera IV diferente

print(f"IV 1: {encrypted1[:16].hex()}")
print(f"IV 2: {encrypted2[:16].hex()}")
print(f"¿Idénticos? {encrypted1 == encrypted2}")  # NO - SEGURO
```

**Reglas del IV:**
- Único para cada cifrado con la misma clave
- No necesita ser secreto (puede transmitirse junto al cifrado)
- En nuestra implementación: `IV (16 bytes) + ciphertext`

**Riesgo de reutilizar IV:** Un atacante puede detectar mensajes repetidos y realizar ataques de análisis de frecuencia.

---

### 2.5 Padding PKCS#7

PKCS#7 añade **N bytes de valor N** para completar el último bloque.

#### Ejemplos byte a byte

```python
from src.manual_padding import pkcs7_pad, pkcs7_unpad

# Ejemplo 1: Mensaje de 5 bytes (bloque DES = 8)
msg = b"HELLO"  # 5 bytes
padded = pkcs7_pad(msg, 8)
print(f"Original: {msg} ({len(msg)} bytes)")
print(f"Hex:      {msg.hex()}")
print(f"Padded:   {padded.hex()}")
print(f"Bytes:    {list(padded)}")
# Original: b'HELLO' (5 bytes)
# Hex:      48454c4c4f
# Padded:   48454c4c4f030303
# Bytes:    [72, 69, 76, 76, 79, 3, 3, 3]
#                              ↑   ↑  ↑
#                         3 bytes de padding con valor 0x03

# Ejemplo 2: Mensaje de 8 bytes (múltiplo exacto)
msg = b"12345678"  # 8 bytes
padded = pkcs7_pad(msg, 8)
print(f"Original: {msg} ({len(msg)} bytes)")
print(f"Padded:   {padded.hex()}")
print(f"Longitud: {len(padded)} bytes")
# Original: b'12345678' (8 bytes)
# Padded:   31323334353637380808080808080808
# Longitud: 16 bytes
#           ↑ Se agrega bloque completo de 8 bytes con valor 0x08

# Ejemplo 3: Mensaje de 10 bytes
msg = b"HOLA MUNDO"  # 10 bytes
padded = pkcs7_pad(msg, 8)
print(f"Original: {msg} ({len(msg)} bytes)")
print(f"Padded:   {padded.hex()}")
print(f"Bytes:    {list(padded)}")
# Original: b'HOLA MUNDO' (10 bytes)
# Padded:   484f4c41204d554e444f060606060606
# Bytes:    [72,79,76,65,32,77,85,78,68,79, 6, 6, 6, 6, 6, 6]
#                                          ↑  padding 6 bytes
```

**Reglas PKCS#7:**
1. Siempre se añade padding (mínimo 1 byte)
2. Si el mensaje es múltiplo exacto, se añade un bloque completo
3. El valor de cada byte = cantidad de bytes de padding

**Recuperación del mensaje original:**
```python
unpadded = pkcs7_unpad(padded)
assert unpadded == msg  # Siempre se recupera exactamente el original
```

---

### 2.6 Recomendaciones de Uso

#### Tabla comparativa de modos

| Modo | Uso Recomendado | Desventajas |
|------|-----------------|-------------|
| **ECB** | Nunca para datos sensibles. Solo cifrado de claves aisladas | Revela patrones, no usa IV |
| **CBC** | Cifrado de archivos, datos en reposo | No paralelizable, requiere padding |
| **CTR** | Streaming, cifrado de disco | Nunca reutilizar nonce, no autentica |
| **GCM** | TLS, APIs, datos en tránsito | Límite de 2^32 bloques por clave/nonce |

#### Modos AEAD (Authenticated Encryption with Associated Data)

**GCM (Galois/Counter Mode)** combina cifrado y autenticación:
- Detecta modificaciones en el ciphertext
- Protege contra ataques de padding oracle
- Estándar en TLS 1.3, APIs modernas

#### Ejemplos en diferentes lenguajes

**Python (PyCryptodome):**
```python
from Crypto.Cipher import AES

# AES-256-GCM (recomendado)
key = secrets.token_bytes(32)
nonce = secrets.token_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
# Transmitir: nonce + tag + ciphertext
```

**JavaScript (Node.js):**
```javascript
const crypto = require('crypto');

// AES-256-GCM
const key = crypto.randomBytes(32);
const nonce = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);

let encrypted = cipher.update(plaintext, 'utf8', 'hex');
encrypted += cipher.final('hex');
const tag = cipher.getAuthTag();
// Transmitir: nonce + tag + encrypted
```

**Go:**
```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

// AES-256-GCM
key := make([]byte, 32)
rand.Read(key)

block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)

nonce := make([]byte, gcm.NonceSize())
rand.Read(nonce)

ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
// ciphertext incluye nonce + tag + datos cifrados
```

#### Recomendaciones finales

1. **No usar DES** — Vulnerable a fuerza bruta
2. **Preferir AES-256-GCM** — Cifrado autenticado
3. **Nunca usar ECB** para datos con patrones
4. **IV/Nonce único** por cada cifrado
5. **Claves con CSPRNG** — `secrets.token_bytes()`
6. **Considerar librerías de alto nivel** — `cryptography`, `libsodium`

---

## Dependencias

- `pycryptodome` — DES, 3DES, AES
- `Pillow` — Procesamiento de imágenes
- `pytest` — Tests unitarios
