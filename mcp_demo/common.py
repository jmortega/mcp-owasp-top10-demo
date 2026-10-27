"""
common.py — Infraestructura compartida por la demo (datos ficticios, auditoría, cripto).

TODO EL CONTENIDO AQUÍ ES FICTICIO Y PARA USO LOCAL/EDUCATIVO.
No hay credenciales reales, ni se contacta con ningún servicio externo.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Auditoría continua (defensa #6 de la charla)
# Un logger central que las rutas SEGURAS usan para dejar traza de cada
# decisión relevante: quién hizo qué, cuándo y con qué contexto.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
audit = logging.getLogger("mcp.audit")


# ---------------------------------------------------------------------------
# "Base de datos" ficticia en memoria
# ---------------------------------------------------------------------------
@dataclass
class User:
    user_id: str
    name: str
    role: str          # "user" | "analyst" | "admin"
    trust_level: int   # 0 (bajo) .. 100 (alto)


# Usuarios de juguete. 'alice' es víctima, 'mallory' es la atacante.
USERS: dict[str, User] = {
    "alice":   User("alice", "Alice (víctima)",  role="user",    trust_level=10),
    "bob":     User("bob", "Bob",                role="user",    trust_level=10),
    "carol":   User("carol", "Carol (analista)", role="analyst", trust_level=50),
    "admin":   User("admin", "Root Admin",       role="admin",   trust_level=100),
    "mallory": User("mallory", "Mallory (atacante)", role="user", trust_level=10),
}


@dataclass
class SessionContext:
    """El 'contexto' que MCP transporta entre agente y herramientas."""
    context_id: str
    owner_user_id: str
    data: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    trust_level: int = 0          # nivel de confianza del contexto (para MCP-3)
    expires_at: float | None = None


# Secretos de juguete (MCP-7). En un sistema real NUNCA estarían en código:
# irían en un gestor de secretos (Vault, AWS Secrets Manager, KMS...).
FAKE_SECRETS = {
    "STRIPE_API_KEY": "sk_test_FAKE_DO_NOT_USE_0000000000demo",
    "INTERNAL_DB_PASSWORD": "fake-db-pass-demo",
    "JWT_SIGNING_KEY": "fake-signing-key-for-the-demo-only",
}

# Clave de firma JWT de la demo (fija y FALSA, solo para que el ejemplo corra).
JWT_SECRET = os.environ.get("DEMO_JWT_SECRET", FAKE_SECRETS["JWT_SIGNING_KEY"])


# ---------------------------------------------------------------------------
# Utilidades de presentación para las demos exploit -> mitigación
# ---------------------------------------------------------------------------
BANNER = (
    "\n" + "=" * 78 + "\n"
    "  ⚠  SERVIDOR MCP DELIBERADAMENTE VULNERABLE — SOLO USO LOCAL/FORMATIVO  ⚠\n"
    "  OWASP MCP Top 10 · BIT UP 2026 · Seguridad en Agentes de IA\n"
    + "=" * 78
)


def section(title: str) -> None:
    print("\n" + "─" * 78)
    print(f"  {title}")
    print("─" * 78)


def show(label: str, value: Any) -> None:
    print(f"   {label:<28} {value}")


def redact(value: str, keep: int = 4) -> str:
    """Enmascara un secreto dejando solo los últimos `keep` caracteres."""
    if not value:
        return value
    return "•" * max(0, len(value) - keep) + value[-keep:]
