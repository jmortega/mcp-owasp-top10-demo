"""
MCP-2 · Inyección de datos contextuales (Context Data Injection)
================================================================

EN QUÉ CONSISTE
    Un atacante inyecta datos maliciosos en la capa de contexto para manipular
    una decisión posterior (un motor de reglas, una autorización, el modelo).
    Es el primo del Prompt Injection, pero sobre los DATOS DE ESTADO, no sobre
    el texto del prompt.

DÓNDE SE VE EN EL CÓDIGO
    - `vulnerable_authorize()` hace `trusted.update(untrusted)`: mezcla datos
      del usuario con los campos de decisión, y además confía en campos extra
      inesperados como "is_admin" o "discount".

EXPLOIT (ver demo())
    El payload del usuario incluye {"is_admin": true, "discount": 100}. Al
    fusionarlo sobre el estado de confianza, la decisión se vuelca a su favor.

MITIGACIÓN (la defensa estrella de la charla: PYDANTIC)
    Conceptual:
      - Trata TODO dato de contexto como entrada NO confiable.
      - Esquema estricto por herramienta; rechaza campos no declarados.
      - Nunca fusiones datos no confiables sobre el estado de decisión.
    Código: `UserContext` con `extra="forbid"` + tipos/validadores. La decisión
    se calcula en el servidor, no se "lee" del payload.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..common import audit


# ─────────────────────────── VERSIÓN VULNERABLE ───────────────────────────
def vulnerable_authorize(user_payload: dict) -> dict:
    """
    Motor de decisión ingenuo: arranca de un estado 'de confianza' y lo
    SOBREESCRIBE con lo que mande el usuario. Clásico 'mass assignment'.
    """
    decision_state = {
        "role": "user",
        "is_admin": False,
        "discount": 0,
        "amount": 0,
    }
    decision_state.update(user_payload)   # 💥 inyección directa sobre la decisión
    approved = decision_state["is_admin"] or decision_state["discount"] >= 50
    return {"approved": approved, "state": decision_state}

# Tabla de cupones del lado del servidor (fuente de verdad, NO del cliente).
_COUPONS = {"WELCOME10": 10, "BLACKFRIDAY": 40}

# ──────────────────────────── VERSIÓN SEGURA ──────────────────────────────
class UserContext(BaseModel):
    """Esquema estricto: solo estos campos, con estos tipos y rangos."""
    model_config = ConfigDict(extra="forbid")  # ← rechaza campos no declarados

    user_id: Annotated[str, Field(min_length=1, max_length=64)]
    amount: Annotated[int, Field(ge=0, le=100_000)]
    coupon: Annotated[str, Field(max_length=16, pattern=r"^[A-Z0-9_-]*$")] = ""


def secure_authorize(user_payload: dict) -> dict:
    """La decisión se deriva de datos validados + estado del servidor."""
    try:
        ctx = UserContext.model_validate(user_payload)   # falla si hay basura
    except ValidationError as e:
        audit.warning("MCP-2 bloqueado: payload inválido (%d errores)",
                      len(e.errors()))
        return {"approved": False, "error": "payload inválido", "details": e.errors()}

    # El descuento NO lo decide el usuario: lo resuelve el servidor.
    discount = _COUPONS.get(ctx.coupon, 0)
    # El rol tampoco viaja en el payload (eso es MCP-10): se consulta aparte.
    approved = discount >= 50  # ningún cupón legítimo llega a 50 -> no se cuela
    audit.info("MCP-2 ok: user=%s amount=%s discount=%s approved=%s",
               ctx.user_id, ctx.amount, discount, approved)
    return {"approved": approved, "discount_applied": discount}


# ───────────────────────────────── DEMO ───────────────────────────────────
def demo() -> dict:
    from ..common import section, show

    section("MCP-2 · Inyección de datos contextuales")

    malicious = {
        "user_id": "mallory",
        "amount": 999,
        "is_admin": True,     # campo inyectado
        "discount": 100,      # campo inyectado
        "coupon": "WELCOME10",
    }
    show("Payload del atacante:", malicious)

    v = vulnerable_authorize(malicious)
    show("❌ VULNERABLE -> approved:", v["approved"])

    s = secure_authorize(malicious)
    show("✅ SEGURO -> approved:", s["approved"])
    show("✅ SEGURO -> motivo:", "campos extra rechazados por extra='forbid'")

    # Un payload legítimo sí pasa la validación.
    ok = secure_authorize({"user_id": "alice", "amount": 20, "coupon": "WELCOME10"})
    show("✅ SEGURO payload válido:", ok)

    return {"vulnerable_approved": v["approved"], "secure_approved": s["approved"]}
