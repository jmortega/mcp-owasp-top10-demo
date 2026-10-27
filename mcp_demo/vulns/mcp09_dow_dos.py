"""
MCP-9 · Denegación de cartera/servicio (DoW / DoS)
==================================================

EN QUÉ CONSISTE
    Herramientas maliciosas o comprometidas se explotan para consumir recursos
    o abusar de las APIs de servicios conectados: costes financieros inesperados
    (Denial of Wallet) o indisponibilidad de servicios críticos (DoS).

DÓNDE SE VE EN EL CÓDIGO
    - `vulnerable_bulk_enrich()` llama a una "API de pago" sin límite de número
      de llamadas ni de presupuesto -> el atacante dispara el gasto.

EXPLOIT (ver demo())
    Mallory pide enriquecer 10.000 registros; cada llamada "cuesta" 0,01€ y no
    hay tope: 100€ en una sola invocación.

MITIGACIÓN
    Conceptual (defensa #2 de la charla: sandboxing + límites):
      - Límites de recursos: nº de llamadas, presupuesto por sesión, timeouts.
      - Rate limiting por usuario/herramienta.
      - Circuit breaker y cuotas en las APIs aguas abajo.
    Código: `BudgetGuard` (tope de coste) + límite de tamaño de lote + timeout.
"""
from __future__ import annotations

import time

from ..common import audit

COST_PER_CALL = 0.01  # € por llamada a la "API de pago" simulada


class _PaidAPI:
    """API externa de pago SIMULADA (no hay red). Solo cuenta coste/llamadas."""

    def __init__(self) -> None:
        self.calls = 0
        self.cost = 0.0

    def enrich(self, record: str) -> str:
        self.calls += 1
        self.cost = round(self.cost + COST_PER_CALL, 4)
        return f"enriched:{record}"


# ─────────────────────────── VERSIÓN VULNERABLE ───────────────────────────
def vulnerable_bulk_enrich(n: int, api: _PaidAPI) -> dict:
    """Sin límites: procesa lo que pidan, cueste lo que cueste."""
    for i in range(n):
        api.enrich(f"rec-{i}")         # 💥 sin tope de llamadas ni presupuesto
    return {"processed": n, "cost_eur": api.cost}


# ──────────────────────────── VERSIÓN SEGURA ──────────────────────────────
class QuotaExceeded(RuntimeError):
    pass


class BudgetGuard:
    """Tope de presupuesto + nº de llamadas + tiempo por invocación."""

    def __init__(self, max_calls: int = 100, max_cost: float = 1.0,
                 max_seconds: float = 2.0) -> None:
        self.max_calls = max_calls
        self.max_cost = max_cost
        self.max_seconds = max_seconds

    def run(self, n: int, api: _PaidAPI) -> dict:
        if n > self.max_calls:
            audit.warning("MCP-9 bloqueado: lote %s > límite %s", n, self.max_calls)
            raise QuotaExceeded(f"lote {n} excede el máximo de {self.max_calls}")
        start = time.time()
        for i in range(n):
            if api.cost + COST_PER_CALL > self.max_cost:
                raise QuotaExceeded(f"presupuesto {self.max_cost}€ agotado")
            if time.time() - start > self.max_seconds:
                raise QuotaExceeded("timeout de la operación")
            api.enrich(f"rec-{i}")
        audit.info("MCP-9 ok: %s registros, coste %.2f€", n, api.cost)
        return {"processed": n, "cost_eur": api.cost}


# ───────────────────────────────── DEMO ───────────────────────────────────
def demo() -> dict:
    from ..common import section, show

    section("MCP-9 · Denegación de cartera/servicio (DoW/DoS)")

    api_v = _PaidAPI()
    v = vulnerable_bulk_enrich(10_000, api_v)
    show("❌ VULNERABLE procesa:", f"{v['processed']} llamadas")
    show("❌ VULNERABLE coste:", f"{v['cost_eur']:.2f} €")

    guard = BudgetGuard(max_calls=100, max_cost=1.0)
    blocked = None
    try:
        guard.run(10_000, _PaidAPI())
    except QuotaExceeded as e:
        blocked = str(e)
    show("✅ SEGURO ante abuso:", f"QuotaExceeded -> {blocked}")
    ok = guard.run(50, _PaidAPI())
    show("✅ SEGURO lote válido:", f"{ok['processed']} llamadas, {ok['cost_eur']:.2f} €")

    return {"vulnerable_cost": v["cost_eur"], "secure_blocked": blocked is not None}
