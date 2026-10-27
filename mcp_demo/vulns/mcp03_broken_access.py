"""
MCP-3 · Control de acceso del protocolo roto (Broken Protocol Access Control)
=============================================================================

EN QUÉ CONSISTE
    Falta de validación de que el servicio que consume el protocolo tiene
    autorización para solicitar o modificar un contexto de nivel superior. Un
    microservicio de confianza 'baja' altera un contexto usado por uno 'alto'.

DÓNDE SE VE EN EL CÓDIGO
    - `vulnerable_update_field()` escribe cualquier campo sin mirar el nivel de
      confianza del llamante ni la sensibilidad del campo.

EXPLOIT (ver demo())
    Un servicio de trust_level=10 modifica el campo "approval_level" de un
    contexto de trust_level=100 y eleva una aprobación.

MITIGACIÓN
    Conceptual:
      - Servicio de autorización CENTRALIZADO: define explícitamente qué
        servicio/rol puede crear/leer/actualizar/eliminar qué campos.
      - Nivel de confianza del emisor >= sensibilidad del campo.
      - Mínimo privilegio por componente.
    Código: `POLICY` (matriz de capacidades) + `secure_update_field()`.
"""
from __future__ import annotations

from ..common import SessionContext, audit

# Contexto de alta confianza de ejemplo.
_HIGH_CTX = SessionContext(
    context_id="ctx-high",
    owner_user_id="admin",
    trust_level=100,
    data={"approval_level": 1, "note": "pedido pendiente"},
)

# Sensibilidad mínima (trust_level) requerida para escribir cada campo.
FIELD_SENSITIVITY = {"note": 10, "approval_level": 90}


# ─────────────────────────── VERSIÓN VULNERABLE ───────────────────────────
def vulnerable_update_field(field: str, value, *, caller_trust: int) -> dict:
    """Escribe el campo sin comprobar nada. 'La red interna es de confianza'."""
    _HIGH_CTX.data[field] = value          # 💥 sin matriz de permisos
    return dict(_HIGH_CTX.data)


# ──────────────────────────── VERSIÓN SEGURA ──────────────────────────────
class AuthzError(PermissionError):
    pass


def secure_update_field(field: str, value, *, caller_trust: int) -> dict:
    """Autorización centralizada: el emisor debe igualar la sensibilidad."""
    required = FIELD_SENSITIVITY.get(field)
    if required is None:
        raise AuthzError(f"campo '{field}' no permitido")
    if caller_trust < required:
        audit.warning("MCP-3 bloqueado: trust=%s intentó escribir '%s' (req %s)",
                      caller_trust, field, required)
        raise AuthzError(
            f"trust {caller_trust} insuficiente para escribir '{field}' (req {required})"
        )
    _HIGH_CTX.data[field] = value
    audit.info("MCP-3 ok: escritura de '%s' por trust=%s", field, caller_trust)
    return dict(_HIGH_CTX.data)


# ───────────────────────────────── DEMO ───────────────────────────────────
def demo() -> dict:
    from ..common import section, show

    section("MCP-3 · Control de acceso del protocolo roto")

    _HIGH_CTX.data["approval_level"] = 1
    show("Estado inicial:", _HIGH_CTX.data)

    v = vulnerable_update_field("approval_level", 99, caller_trust=10)
    show("❌ VULNERABLE (trust 10 escribe):", v["approval_level"])

    _HIGH_CTX.data["approval_level"] = 1
    blocked = None
    try:
        secure_update_field("approval_level", 99, caller_trust=10)
    except AuthzError as e:
        blocked = str(e)
    show("✅ SEGURO ante trust bajo:", f"AuthzError -> {blocked}")
    ok = secure_update_field("approval_level", 2, caller_trust=100)
    show("✅ SEGURO con trust alto:", ok["approval_level"])

    return {"vulnerable_level": v["approval_level"], "secure_blocked": blocked is not None}
