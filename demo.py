#!/usr/bin/env python3
"""
demo.py — Ejecuta las 10 demos exploit -> mitigación en local, sin necesidad
de un cliente MCP ni de un LLM.

Uso:
    python demo.py            # todas
    python demo.py MCP-3      # solo una (por código)
"""
from __future__ import annotations

import sys

from mcp_demo.common import BANNER
from mcp_demo.vulns import CATALOG


def main(argv: list[str]) -> int:
    print(BANNER)
    wanted = {a.upper() for a in argv[1:]}
    results = {}
    for code, _title, module in CATALOG:
        if wanted and code not in wanted:
            continue
        results[code] = module.demo()

    print("\n" + "=" * 78)
    print("  RESUMEN")
    print("=" * 78)
    for code, _title, _m in CATALOG:
        if code not in results:
            continue
        r = results[code]
        secure_ok = r.get("secure_blocked") or r.get("secure_clean") \
            or r.get("secure_ciphertext") or r.get("secure_no_secret") \
            or (r.get("secure_approved") is False)
        print(f"   {code:<7} vulnerable=explotable   mitigado={'✅' if secure_ok else '⚠'}")
    print("\n  (Las líneas ✅ son las versiones seguras bloqueando el ataque.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
