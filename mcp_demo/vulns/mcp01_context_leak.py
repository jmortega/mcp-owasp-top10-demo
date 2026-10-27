"""
MCP-1 · Fuga del contexto de sesión (Session Context Leakage)
=============================================================

EN QUÉ CONSISTE
    Exposición de datos de un usuario/microservicio a otro no autorizado por
    una gestión incorrecta del identificador de contexto. En la práctica es un
    IDOR (Insecure Direct Object Reference) sobre el "context_id": si el id es
    adivinable y el servidor no comprueba la propiedad, cualquiera lee el
    contexto de otro.

DÓNDE SE VE EN EL CÓDIGO
    - `next_context_id()`           -> ids secuenciales y predecibles.
    - `vulnerable_get_context()`    -> NO comprueba quién es el dueño.

EXPLOIT (ver demo())
    Alice crea el contexto "ctx-1" con datos sensibles. Mallory pide "ctx-1"
    (o simplemente prueba ids correlativos) y lo lee entero.

MITIGACIÓN
    Conceptual:
      - Identificadores NO adivinables (UUIDv4 / secrets.token_urlsafe).
      - Cada contexto ligado al usuario autenticado y validado en cada acceso.
      - Principio de mínimo privilegio: solo ve su propio contexto.
    Código: `secure_get_context()` exige `caller` y comprueba propiedad.
"""
from __future__ import annotations

import itertools
import secrets

from ..common import USERS, SessionContext, audit

# Almacén en memoria de contextos para esta demo.
_CONTEXTS: dict[str, SessionContext] = {}

# ❌ VULNERABLE: contador global -> ids secuenciales "ctx-1", "ctx-2"...
_counter = itertools.count(1)


def next_context_id_vulnerable() -> str:
    return f"ctx-{next(_counter)}"


def next_context_id_secure() -> str:
    # ✅ 128 bits de aleatoriedad: imposible de adivinar o enumerar.
    return f"ctx-{secrets.token_urlsafe(24)}"


def create_context(owner: str, data: dict, *, secure: bool) -> str:
    cid = next_context_id_secure() if secure else next_context_id_vulnerable()
    _CONTEXTS[cid] = SessionContext(context_id=cid, owner_user_id=owner, data=data)
    return cid


# ─────────────────────────── VERSIÓN VULNERABLE ───────────────────────────
def vulnerable_get_context(context_id: str) -> dict:
    """Devuelve el contexto SIN comprobar quién lo pide. IDOR de manual."""
    ctx = _CONTEXTS.get(context_id)
    if ctx is None:
        raise KeyError("contexto no encontrado")
    return ctx.data  # 💥 cualquiera que acierte el id ve estos datos


# ──────────────────────────── VERSIÓN SEGURA ──────────────────────────────
class AccessDenied(PermissionError):
    pass


def secure_get_context(context_id: str, caller: str) -> dict:
    """Comprueba la PROPIEDAD del contexto antes de devolverlo."""
    if caller not in USERS:
        raise AccessDenied("llamante desconocido")
    ctx = _CONTEXTS.get(context_id)
    if ctx is None:
        # Mensaje genérico: no filtramos si el id existe o no.
        raise AccessDenied("contexto no encontrado o sin acceso")
    if ctx.owner_user_id != caller:
        audit.warning("MCP-1 bloqueado: %s intentó leer contexto de %s",
                      caller, ctx.owner_user_id)
        raise AccessDenied("contexto no encontrado o sin acceso")
    audit.info("MCP-1 ok: %s leyó su propio contexto %s", caller, context_id)
    return ctx.data


# ───────────────────────────────── DEMO ───────────────────────────────────
def demo() -> dict:
    from ..common import section, show

    section("MCP-1 · Fuga del contexto de sesión (IDOR)")

    # Alice guarda algo sensible con el servidor VULNERABLE (id secuencial).
    victim_data = {"iban": "ES76 0000 1111 2222", "notas": "despido confidencial"}
    cid = create_context("alice", victim_data, secure=False)
    show("Alice crea contexto:", cid)

    # Mallory simplemente prueba ids correlativos.
    guessed = "ctx-1"
    stolen = vulnerable_get_context(guessed)
    show("Mallory pide:", guessed)
    show("❌ VULNERABLE devuelve:", stolen)

    # Con la versión segura: id imposible de adivinar + control de propiedad.
    cid_s = create_context("alice", victim_data, secure=True)
    show("Alice (seguro) crea:", cid_s)
    blocked = None
    try:
        secure_get_context(cid_s, caller="mallory")
    except AccessDenied as e:
        blocked = str(e)
    show("✅ SEGURO ante Mallory:", f"AccessDenied -> {blocked}")
    show("✅ SEGURO con la dueña:", secure_get_context(cid_s, caller="alice"))

    return {"vulnerable_leaked": stolen, "secure_blocked": blocked is not None}
