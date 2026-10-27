"""
MCP-4 · Exposición del estado del modelo (Model State Exposure)
===============================================================

EN QUÉ CONSISTE
    Fuga de información sobre la arquitectura, parámetros, prompts de sistema o
    datos de entrenamiento a través de METADATOS o RESPUESTAS del protocolo
    (incluidas trazas de error). Facilita ataques de inferencia o de modelos
    adversarios.

DÓNDE SE VE EN EL CÓDIGO
    - `vulnerable_infer()` devuelve en la respuesta/metadatos el system prompt,
      el nombre y pesos del modelo y, ante un fallo, la traza completa.

EXPLOIT (ver demo())
    El cliente provoca un error (o simplemente lee los metadatos) y obtiene el
    system prompt interno, la versión del modelo y el stack trace con rutas.

MITIGACIÓN
    Conceptual:
      - Separa la respuesta pública de los metadatos internos.
      - Mensajes de error genéricos; el detalle va a logs internos con un id de
        correlación, nunca al cliente.
      - No expongas system prompt, pesos ni configuración del modelo.
    Código: `secure_infer()` devuelve solo el resultado + un error_id opaco.
"""
from __future__ import annotations

import traceback
import uuid

from ..common import audit

# "Secretos" internos del modelo que NO deberían salir nunca.
_SYSTEM_PROMPT = "Eres el motor de fraude interno. Umbral de bloqueo = 0.82."
_MODEL_META = {"model": "fraud-scorer", "version": "4.8-internal", "weights_sha": "deadbeef"}


def _score(text: str) -> float:
    if text is None:
        raise ValueError("texto nulo")        # para provocar un error de ejemplo
    return round(min(1.0, len(text) / 100), 3)


# ─────────────────────────── VERSIÓN VULNERABLE ───────────────────────────
def vulnerable_infer(text: str) -> dict:
    """Mezcla resultado con tripas del modelo y filtra el stack en errores."""
    try:
        score = _score(text)
        return {
            "score": score,
            # 💥 metadatos internos devueltos al cliente
            "_debug": {
                "system_prompt": _SYSTEM_PROMPT,
                "model_meta": _MODEL_META,
            },
        }
    except Exception:
        # 💥 stack trace completo (rutas, nombres internos) al cliente
        return {"error": traceback.format_exc()}


# ──────────────────────────── VERSIÓN SEGURA ──────────────────────────────
def secure_infer(text: str) -> dict:
    """Devuelve solo lo público; el detalle de error queda en logs internos."""
    try:
        return {"score": _score(text)}        # nada de system prompt ni meta
    except Exception as exc:  # noqa: BLE001  (capturamos para no filtrar nada)
        error_id = uuid.uuid4().hex[:12]
        # El detalle va al log interno, correlacionable por error_id.
        audit.error("MCP-4 error_id=%s: %r", error_id, exc)
        return {"error": "error interno", "error_id": error_id}


# ───────────────────────────────── DEMO ───────────────────────────────────
def demo() -> dict:
    from ..common import section, show

    section("MCP-4 · Exposición del estado del modelo")

    v_ok = vulnerable_infer("pago sospechoso")
    show("❌ VULNERABLE filtra:", v_ok.get("_debug"))
    v_err = vulnerable_infer(None)
    leaked_trace = "Traceback" in v_err.get("error", "")
    show("❌ VULNERABLE en error:", "stack trace completo" if leaked_trace else "—")

    s_ok = secure_infer("pago sospechoso")
    show("✅ SEGURO devuelve:", s_ok)
    s_err = secure_infer(None)
    show("✅ SEGURO en error:", s_err)

    return {
        "vulnerable_leaked_prompt": "_debug" in v_ok,
        "secure_clean": "_debug" not in s_ok and "error_id" in s_err,
    }
