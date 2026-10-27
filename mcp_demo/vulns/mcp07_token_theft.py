"""
MCP-7 · Exposición de datos sensibles y robo de tokens (Sensitive Data Exposure)
================================================================================

EN QUÉ CONSISTE
    Entornos MCP mal configurados y malas prácticas de manejo de datos exponen
    claves API, tokens y credenciales (en respuestas, logs, mensajes de error,
    variables de entorno devueltas al cliente...).

DÓNDE SE VE EN EL CÓDIGO
    - `vulnerable_get_config()` devuelve los secretos tal cual en la respuesta.
    - `vulnerable_log_request()` escribe el token en el log.

EXPLOIT (ver demo())
    El cliente pide la 'config' y recibe STRIPE_API_KEY y la password de BD.

MITIGACIÓN
    Conceptual:
      - Los secretos NUNCA salen en respuestas ni en logs.
      - Gestión con un secret manager; en código, `SecretStr` de Pydantic evita
        volcarlos por accidente (repr/serialización los enmascara).
      - Tokens de alcance mínimo y vida corta; redacción en logs.
    Código: `AppConfig` con `SecretStr` + `secure_get_config()` que solo expone
    metadatos no sensibles.
"""
from __future__ import annotations

from pydantic import BaseModel, SecretStr

from ..common import FAKE_SECRETS, audit, redact


# ─────────────────────────── VERSIÓN VULNERABLE ───────────────────────────
def vulnerable_get_config() -> dict:
    """Devuelve la configuración entera, secretos incluidos."""
    return {
        "stripe_api_key": FAKE_SECRETS["STRIPE_API_KEY"],   # 💥
        "db_password": FAKE_SECRETS["INTERNAL_DB_PASSWORD"], # 💥
        "region": "eu-west-1",
    }


def vulnerable_log_request(token: str) -> str:
    """Registra el token en claro: cualquiera con acceso a logs lo roba."""
    line = f"request autenticada con token={token}"   # 💥 secreto en el log
    return line


# ──────────────────────────── VERSIÓN SEGURA ──────────────────────────────
class AppConfig(BaseModel):
    """SecretStr evita que el secreto aparezca en repr(), dict() o logs."""
    stripe_api_key: SecretStr
    db_password: SecretStr
    region: str


_CONFIG = AppConfig(
    stripe_api_key=FAKE_SECRETS["STRIPE_API_KEY"],
    db_password=FAKE_SECRETS["INTERNAL_DB_PASSWORD"],
    region="eu-west-1",
)


def secure_get_config() -> dict:
    """Expone solo lo NO sensible; los secretos se quedan en el servidor."""
    audit.info("MCP-7 ok: config solicitada (sin secretos en la respuesta)")
    return {"region": _CONFIG.region, "has_stripe_key": True}  # metadatos, no valores


def secure_log_request(token: str) -> str:
    """Registra el token REDACTADO."""
    line = f"request autenticada con token={redact(token)}"
    audit.info(line)
    return line


# ───────────────────────────────── DEMO ───────────────────────────────────
def demo() -> dict:
    from ..common import section, show

    section("MCP-7 · Exposición de datos sensibles / robo de tokens")

    v = vulnerable_get_config()
    show("❌ VULNERABLE config:", v)
    show("❌ VULNERABLE log:", vulnerable_log_request("tok_live_SECRET_123456"))

    s = secure_get_config()
    show("✅ SEGURO config:", s)
    show("✅ SEGURO log:", secure_log_request("tok_live_SECRET_123456"))
    # SecretStr enmascara el valor incluso si alguien imprime el objeto:
    show("✅ SecretStr repr:", str(_CONFIG.stripe_api_key))

    return {
        "vulnerable_leaked_key": "stripe_api_key" in v,
        "secure_no_secret": "stripe_api_key" not in s,
    }
