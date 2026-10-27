"""
MCP-10 · Omisión de autenticación (Authentication Bypass)
=========================================================

EN QUÉ CONSISTE
    Mecanismos de autenticación débiles, mal configurados o mal aplicados
    permiten eludir los controles: suplantar usuarios/servidores y obtener
    acceso no autorizado.

DÓNDE SE VE EN EL CÓDIGO
    - `vulnerable_admin_action()` CONFÍA en campos que manda el cliente:
      `role`, `is_admin` o un flag `debug` que salta la comprobación.

EXPLOIT (ver demo())
    Mallory manda {"role": "admin"} (o {"debug": true}) y ejecuta la acción de
    administrador sin tener ese rol.

MITIGACIÓN
    Conceptual (control de acceso centralizado):
      - El rol NUNCA viaja en el payload del cliente: se deriva de un token
        firmado y verificado en el servidor (JWT con firma HS256/RS256).
      - Sin backdoors de 'debug'. Verificación en cada microservicio.
    Código: `issue_token()` firma; `secure_admin_action()` verifica la firma y
    lee el rol del claim, no del cuerpo de la petición.
"""
from __future__ import annotations

import time

import jwt  # PyJWT

from ..common import JWT_SECRET, USERS, audit


# ─────────────────────────── VERSIÓN VULNERABLE ───────────────────────────
def vulnerable_admin_action(request: dict) -> str:
    """Decide si eres admin leyendo lo que TÚ dices que eres."""
    if request.get("debug"):                       # 💥 backdoor de debug
        return "ACCIÓN ADMIN ejecutada (modo debug)"
    if request.get("role") == "admin" or request.get("is_admin"):  # 💥 claim del cliente
        return "ACCIÓN ADMIN ejecutada"
    return "denegado"


# ──────────────────────────── VERSIÓN SEGURA ──────────────────────────────
class AuthError(PermissionError):
    pass


def issue_token(user_id: str) -> str:
    """El servidor de identidad emite un JWT firmado con el rol REAL."""
    user = USERS[user_id]
    payload = {"sub": user.user_id, "role": user.role, "exp": time.time() + 300}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def secure_admin_action(token: str) -> str:
    """Verifica la firma y lee el rol del claim, no del cuerpo."""
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError as e:
        audit.warning("MCP-10 bloqueado: token inválido (%s)", e)
        raise AuthError("token inválido") from e
    if claims.get("role") != "admin":
        audit.warning("MCP-10 bloqueado: %s no es admin", claims.get("sub"))
        raise AuthError("se requiere rol admin")
    audit.info("MCP-10 ok: acción admin por %s", claims.get("sub"))
    return "ACCIÓN ADMIN ejecutada"


# ───────────────────────────────── DEMO ───────────────────────────────────
def demo() -> dict:
    from ..common import section, show

    section("MCP-10 · Omisión de autenticación (Authentication Bypass)")

    show("❌ VULNERABLE con role=admin:", vulnerable_admin_action({"role": "admin"}))
    show("❌ VULNERABLE con debug=true:", vulnerable_admin_action({"debug": True}))

    # Seguro: Mallory no puede forjar un token admin sin la clave de firma.
    mallory_token = issue_token("mallory")          # su token real es rol "user"
    blocked = None
    try:
        secure_admin_action(mallory_token)
    except AuthError as e:
        blocked = str(e)
    show("✅ SEGURO con token de Mallory:", f"AuthError -> {blocked}")
    show("✅ SEGURO con token admin:", secure_admin_action(issue_token("admin")))
    # Forjar un token cambiando el claim sin la clave tampoco cuela:
    forged = jwt.encode({"sub": "mallory", "role": "admin"},
                        "clave-equivocada-que-mallory-no-conoce-xxxxx",
                        algorithm="HS256")
    forged_blocked = None
    try:
        secure_admin_action(forged)
    except AuthError as e:
        forged_blocked = str(e)
    show("✅ SEGURO con token forjado:", f"AuthError -> {forged_blocked}")

    return {
        "vulnerable_bypassed": "ejecutada" in vulnerable_admin_action({"role": "admin"}),
        "secure_blocked": blocked is not None and forged_blocked is not None,
    }
