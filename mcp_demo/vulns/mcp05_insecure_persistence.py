"""
MCP-5 · Persistencia insegura del contexto (Insecure Context Persistence)
=========================================================================

EN QUÉ CONSISTE
    Almacenar el historial de contexto en una base de datos/caché sin cifrado o
    con políticas de retención débiles. Quien comprometa el almacenamiento (un
    backup, un volcado de caché) obtiene todo el historial y el contexto de
    negocio sensible.

DÓNDE SE VE EN EL CÓDIGO
    - `vulnerable_store()` escribe el contexto en claro y sin caducidad.

EXPLOIT (ver demo())
    Se inspecciona el "almacenamiento" y se lee el contenido sensible en claro.

MITIGACIÓN
    Conceptual:
      - Cifrado en reposo de TODO almacén de contexto.
      - TTL cortos y obligatorios para contextos sensibles.
      - Mecanismo de revocación (borrado/expiración) al cerrar sesión o ante
        anomalías.
    Código: `SecureContextStore` cifra con Fernet (AES-128-CBC + HMAC) y aplica
    TTL; al expirar, el dato ya no es recuperable.
"""
from __future__ import annotations

import time

from cryptography.fernet import Fernet, InvalidToken

from ..common import audit


# ─────────────────────────── VERSIÓN VULNERABLE ───────────────────────────
class VulnerableContextStore:
    """Diccionario 'de caché' en claro, sin TTL. Un volcado lo revela todo."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def store(self, key: str, value: str) -> None:
        self._data[key] = value            # 💥 texto plano

    def raw_dump(self) -> dict[str, str]:
        """Simula el acceso de un atacante al backup/volcado de la caché."""
        return dict(self._data)


# ──────────────────────────── VERSIÓN SEGURA ──────────────────────────────
class SecureContextStore:
    """Cifrado en reposo + TTL. Un volcado solo revela bytes cifrados."""

    def __init__(self, key: bytes | None = None, ttl_seconds: int = 300) -> None:
        self._fernet = Fernet(key or Fernet.generate_key())
        self._ttl = ttl_seconds
        self._blobs: dict[str, tuple[bytes, float]] = {}

    def store(self, key: str, value: str) -> None:
        token = self._fernet.encrypt(value.encode())
        self._blobs[key] = (token, time.time() + self._ttl)
        audit.info("MCP-5 ok: contexto '%s' cifrado (ttl=%ss)", key, self._ttl)

    def retrieve(self, key: str) -> str | None:
        item = self._blobs.get(key)
        if item is None:
            return None
        token, expires = item
        if time.time() > expires:          # TTL caducado -> se revoca
            self._blobs.pop(key, None)
            audit.info("MCP-5: contexto '%s' expirado y revocado", key)
            return None
        try:
            return self._fernet.decrypt(token).decode()
        except InvalidToken:
            return None

    def raw_dump(self) -> dict[str, bytes]:
        """Lo que vería un atacante en el backup: solo ciphertext."""
        return {k: v[0] for k, v in self._blobs.items()}


# ───────────────────────────────── DEMO ───────────────────────────────────
def demo() -> dict:
    from ..common import section, show

    section("MCP-5 · Persistencia insegura del contexto")

    sensitive = "conversación: cliente X quiere vender filial por 12M€"

    vstore = VulnerableContextStore()
    vstore.store("alice:session", sensitive)
    dump_v = vstore.raw_dump()
    show("❌ VULNERABLE backup:", dump_v["alice:session"])

    sstore = SecureContextStore(ttl_seconds=300)
    sstore.store("alice:session", sensitive)
    dump_s = sstore.raw_dump()
    show("✅ SEGURO backup:", dump_s["alice:session"][:48] + b"...")
    show("✅ SEGURO (dueño):", sstore.retrieve("alice:session"))

    # TTL: un store con ttl=0 ya no devuelve nada (revocación por caducidad).
    tmp = SecureContextStore(ttl_seconds=0)
    tmp.store("k", sensitive)
    time.sleep(0.01)
    show("✅ SEGURO tras TTL:", tmp.retrieve("k"))

    leaked = sensitive in dump_v["alice:session"]
    cipher_ok = sensitive.encode() not in dump_s["alice:session"]
    return {"vulnerable_plaintext": leaked, "secure_ciphertext": cipher_ok}
