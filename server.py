#!/usr/bin/env python3
"""
server.py — Servidor MCP real (FastMCP) que expone las herramientas de la demo.

  ⚠  POR DEFECTO ARRANCA EN MODO *VULNERABLE* (para la charla / MCP Inspector).
     Exporta MCP_SECURE=1 para registrar las versiones endurecidas.

  Transporte stdio (por defecto). Para probarlo:
      python server.py                      # modo vulnerable
      MCP_SECURE=1 python server.py         # modo seguro
      npx @modelcontextprotocol/inspector python server.py   # UI de pruebas

  Para Claude Desktop, añade a claude_desktop_config.json:
      "mcpServers": {
        "owasp-mcp-demo": { "command": "python", "args": ["/ruta/server.py"] }
      }

Este servidor es material FORMATIVO. No lo expongas en red ni lo conectes a
datos o servicios reales.
"""
from __future__ import annotations

import os
import sys

from mcp.server.fastmcp import FastMCP

from mcp_demo import defenses
from mcp_demo.common import audit
from mcp_demo.vulns import (
    mcp01_context_leak as m1,
    mcp02_context_injection as m2,
    mcp03_broken_access as m3,
    mcp04_model_state_exposure as m4,
    mcp07_token_theft as m7,
    mcp09_dow_dos as m9,
    mcp10_auth_bypass as m10,
)

SECURE = os.environ.get("MCP_SECURE") == "1"
MODE = "SEGURO" if SECURE else "VULNERABLE"

mcp = FastMCP(f"owasp-mcp-demo[{MODE}]")

# Un contexto de ejemplo para la herramienta de MCP-1.
_SEED_CID = m1.create_context("alice", {"iban": "ES76...", "nota": "confidencial"},
                              secure=SECURE)
audit.info("server arrancado en modo %s (contexto semilla=%s)", MODE, _SEED_CID)


@mcp.tool()
def get_context(context_id: str, caller: str = "anon") -> dict:
    """[MCP-1] Lee un contexto de sesión por su id."""
    if SECURE:
        return m1.secure_get_context(context_id, caller=caller)
    return m1.vulnerable_get_context(context_id)


@mcp.tool()
def authorize(payload: dict) -> dict:
    """[MCP-2] Evalúa una autorización a partir de datos de contexto."""
    return m2.secure_authorize(payload) if SECURE else m2.vulnerable_authorize(payload)


@mcp.tool()
def update_context_field(field: str, value: int, caller_trust: int = 10) -> dict:
    """[MCP-3] Actualiza un campo de un contexto de alta confianza."""
    if SECURE:
        return m3.secure_update_field(field, value, caller_trust=caller_trust)
    return m3.vulnerable_update_field(field, value, caller_trust=caller_trust)


@mcp.tool()
def infer(text: str) -> dict:
    """[MCP-4] Puntúa un texto con el 'motor de fraude' interno."""
    return m4.secure_infer(text) if SECURE else m4.vulnerable_infer(text)


@mcp.tool()
def get_config() -> dict:
    """[MCP-7] Devuelve la configuración del servidor."""
    return m7.secure_get_config() if SECURE else m7.vulnerable_get_config()


@mcp.tool()
def bulk_enrich(n: int) -> dict:
    """[MCP-9] Enriquece n registros contra una API de pago (simulada)."""
    api = m9._PaidAPI()
    if SECURE:
        return m9.BudgetGuard().run(n, api)
    return m9.vulnerable_bulk_enrich(n, api)


@mcp.tool()
def admin_action(role: str = "user", debug: bool = False, token: str = "") -> str:
    """[MCP-10] Ejecuta una acción de administrador."""
    if SECURE:
        return m10.secure_admin_action(token)
    return m10.vulnerable_admin_action({"role": role, "debug": debug})


@mcp.tool()
def send_payment(to: str, amount: int, human_approved: bool = False) -> str:
    """[Human-in-the-loop] Envía un pago (acción crítica, requiere aprobación)."""
    if SECURE:
        return defenses.guard_action(
            "send_payment", lambda: f"{amount}€ enviados a {to}",
            human_approved=human_approved, request_id=f"pay-{to}")
    return f"{amount}€ enviados a {to}"   # vulnerable: sin confirmación


if __name__ == "__main__":
    print(f"[owasp-mcp-demo] modo {MODE} — transporte stdio", file=sys.stderr)
    mcp.run()
