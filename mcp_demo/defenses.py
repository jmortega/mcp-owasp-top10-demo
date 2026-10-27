"""
defenses.py — Defensas transversales de la charla que no mapean a un único
número del OWASP MCP Top 10 pero aplican a varias categorías.

  · Human-in-the-loop (defensa #3): confirmación humana para acciones
    irreversibles o críticas (borrar, pagar, enviar comunicaciones).
  · Auditoría continua (defensa #6): ya implementada con el logger `audit`
    de common.py, que las rutas seguras usan en cada decisión.
"""
from __future__ import annotations

from typing import Callable

from .common import audit

# Acciones consideradas críticas/irreversibles -> exigen aprobación humana.
CRITICAL_ACTIONS = {"send_payment", "delete_data", "send_email", "wire_transfer"}


class ApprovalRequired(Exception):
    """Se lanza cuando una acción crítica necesita aprobación y no la tiene."""

    def __init__(self, action: str, request_id: str) -> None:
        super().__init__(f"La acción '{action}' requiere aprobación humana "
                         f"(request_id={request_id})")
        self.action = action
        self.request_id = request_id


def classify_risk(action: str) -> str:
    """Clasifica la acción por riesgo (defensa: 'clasifica las acciones')."""
    return "critical" if action in CRITICAL_ACTIONS else "low"


def guard_action(action: str, fn: Callable, *args,
                 human_approved: bool = False, request_id: str = "req-0", **kwargs):
    """
    Ejecuta `fn` solo si:
      - la acción es de bajo riesgo, o
      - es crítica y hay aprobación humana explícita (human_approved=True).
    Registra siempre la decisión (auditoría continua).
    """
    risk = classify_risk(action)
    if risk == "critical" and not human_approved:
        audit.warning("HITL: '%s' PARADA, requiere aprobación (req=%s)", action, request_id)
        raise ApprovalRequired(action, request_id)
    result = fn(*args, **kwargs)
    audit.info("HITL: '%s' ejecutada (riesgo=%s, aprobada=%s, req=%s)",
               action, risk, human_approved, request_id)
    return result
