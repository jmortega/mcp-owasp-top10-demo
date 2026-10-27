"""
Tests: por cada vulnerabilidad comprobamos dos cosas:
  1) la versión VULNERABLE es efectivamente explotable, y
  2) la versión SEGURA bloquea el ataque.
Ejecutar:  pytest -q
"""
from __future__ import annotations

import pytest

from mcp_demo import defenses
from mcp_demo.vulns import (
    mcp01_context_leak as m1,
    mcp02_context_injection as m2,
    mcp03_broken_access as m3,
    mcp04_model_state_exposure as m4,
    mcp05_insecure_persistence as m5,
    mcp06_tool_impersonation as m6,
    mcp07_token_theft as m7,
    mcp08_rug_pull as m8,
    mcp09_dow_dos as m9,
    mcp10_auth_bypass as m10,
)


def test_mcp01_idor():
    cid = m1.create_context("alice", {"secreto": 1}, secure=False)
    assert m1.vulnerable_get_context(cid) == {"secreto": 1}          # explotable
    cid_s = m1.create_context("alice", {"secreto": 1}, secure=True)
    with pytest.raises(m1.AccessDenied):                             # mitigado
        m1.secure_get_context(cid_s, caller="mallory")
    assert m1.secure_get_context(cid_s, caller="alice") == {"secreto": 1}


def test_mcp02_injection():
    payload = {"user_id": "m", "amount": 1, "is_admin": True, "discount": 100}
    assert m2.vulnerable_authorize(payload)["approved"] is True       # explotable
    assert m2.secure_authorize(payload)["approved"] is False          # mitigado


def test_mcp03_broken_access():
    m3._HIGH_CTX.data["approval_level"] = 1
    assert m3.vulnerable_update_field("approval_level", 99, caller_trust=10)["approval_level"] == 99
    with pytest.raises(m3.AuthzError):
        m3.secure_update_field("approval_level", 99, caller_trust=10)


def test_mcp04_model_exposure():
    assert "_debug" in m4.vulnerable_infer("x")                       # filtra
    clean = m4.secure_infer("x")
    assert "_debug" not in clean and "score" in clean                 # limpio
    err = m4.secure_infer(None)
    assert "error_id" in err and "Traceback" not in str(err)


def test_mcp05_persistence():
    secret = "dato ultra sensible"
    vs = m5.VulnerableContextStore(); vs.store("k", secret)
    assert secret in vs.raw_dump()["k"]                               # texto plano
    ss = m5.SecureContextStore(ttl_seconds=300); ss.store("k", secret)
    assert secret.encode() not in ss.raw_dump()["k"]                  # cifrado
    assert ss.retrieve("k") == secret


def test_mcp06_impersonation():
    vreg = m6.VulnerableRegistry()
    vreg.register("send_payment", m6.legit_send_payment, m6._LEGIT_DESC)
    vreg.register("send_payment", m6.evil_send_payment, "maliciosa")
    assert "IMPOSTORA" in vreg.resolve("send_payment")("x", 1)        # secuestrada
    allow = {"send_payment": m6._fingerprint("send_payment", m6._LEGIT_DESC)}
    sreg = m6.SecureRegistry(allow)
    sreg.register("send_payment", m6.legit_send_payment, m6._LEGIT_DESC)
    with pytest.raises(m6.ShadowToolError):
        sreg.register("send_payment", m6.evil_send_payment, "maliciosa")


def test_mcp07_token_theft():
    assert "stripe_api_key" in m7.vulnerable_get_config()             # filtra clave
    assert "stripe_api_key" not in m7.secure_get_config()             # no la expone
    assert "SECRET" not in m7.secure_log_request("tok_live_SECRET")   # log redactado


def test_mcp08_rug_pull():
    vt = m8.MutableTool(m8.weather_ok, "d"); vt.rug_pull(m8.weather_evil, "d")
    assert "MALICIOSA" in m8.vulnerable_invoke(vt, "Madrid")          # explotable
    st = m8.PinnedTool(m8.weather_ok, "d"); st.rug_pull(m8.weather_evil, "d")
    with pytest.raises(m8.RugPullDetected):
        st.invoke("Madrid")


def test_mcp09_dow_dos():
    v = m9.vulnerable_bulk_enrich(10_000, m9._PaidAPI())
    assert v["cost_eur"] > 50                                         # gasto sin tope
    with pytest.raises(m9.QuotaExceeded):
        m9.BudgetGuard(max_calls=100).run(10_000, m9._PaidAPI())
    assert m9.BudgetGuard().run(50, m9._PaidAPI())["processed"] == 50


def test_mcp10_auth_bypass():
    assert "ejecutada" in m10.vulnerable_admin_action({"role": "admin"})
    assert "ejecutada" in m10.vulnerable_admin_action({"debug": True})
    with pytest.raises(m10.AuthError):
        m10.secure_admin_action(m10.issue_token("mallory"))
    assert "ejecutada" in m10.secure_admin_action(m10.issue_token("admin"))


def test_human_in_the_loop():
    with pytest.raises(defenses.ApprovalRequired):
        defenses.guard_action("send_payment", lambda: "ok", human_approved=False)
    assert defenses.guard_action("send_payment", lambda: "ok", human_approved=True) == "ok"
    # acción de bajo riesgo no requiere aprobación
    assert defenses.guard_action("read_data", lambda: "ok") == "ok"
