"""Colección ordenada de las 10 vulnerabilidades del OWASP MCP Top 10."""
from __future__ import annotations

from . import (
    mcp01_context_leak,
    mcp02_context_injection,
    mcp03_broken_access,
    mcp04_model_state_exposure,
    mcp05_insecure_persistence,
    mcp06_tool_impersonation,
    mcp07_token_theft,
    mcp08_rug_pull,
    mcp09_dow_dos,
    mcp10_auth_bypass,
)

# (código, título corto, módulo)
CATALOG = [
    ("MCP-1", "Fuga del contexto de sesión", mcp01_context_leak),
    ("MCP-2", "Inyección de datos contextuales", mcp02_context_injection),
    ("MCP-3", "Control de acceso del protocolo roto", mcp03_broken_access),
    ("MCP-4", "Exposición del estado del modelo", mcp04_model_state_exposure),
    ("MCP-5", "Persistencia insegura del contexto", mcp05_insecure_persistence),
    ("MCP-6", "Imitación de herramientas / Shadow MCP", mcp06_tool_impersonation),
    ("MCP-7", "Exposición de datos sensibles / robo de tokens", mcp07_token_theft),
    ("MCP-8", "Rug Pull (retirada de confianza)", mcp08_rug_pull),
    ("MCP-9", "Denegación de cartera/servicio (DoW/DoS)", mcp09_dow_dos),
    ("MCP-10", "Omisión de autenticación", mcp10_auth_bypass),
]
