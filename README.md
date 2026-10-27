# 🛡️ OWASP MCP Top 10 — Servidor MCP vulnerable + mitigaciones (PoC)

> Prueba de concepto para la charla **«Seguridad en Agentes de IA: implementando
> Model Context Protocol (MCP) de forma segura con el OWASP MCP Top 10»** — BIT UP 2026.
>
> Un **servidor MCP deliberadamente vulnerable** que implementa las 10 categorías
> del OWASP MCP Top 10, y al lado la **versión endurecida** de cada una, con las
> defensas de la charla: **Pydantic**, sandboxing/límites, human-in-the-loop,
> aislamiento y cifrado de contexto, control de acceso centralizado y auditoría.

> ### ⚠️ Aviso
> Este proyecto es **material formativo**, al estilo de *OWASP Juice Shop* o *DVWA*.
> Contiene vulnerabilidades **a propósito**. Todos los datos y "secretos" son
> **ficticios**, todo corre **en local** y **no se contacta con ningún servicio
> externo**. **No lo despliegues en red, no lo conectes a datos o APIs reales y no
> reutilices su código inseguro en producción.** Úsalo solo en un entorno aislado.

---

## 📑 Índice

1. [Qué incluye](#-qué-incluye)
2. [Instalación y ejecución rápida](#-instalación-y-ejecución-rápida)
3. [Arquitectura del proyecto](#-arquitectura-del-proyecto)
4. [Cómo conectarlo a un cliente MCP](#-cómo-conectarlo-a-un-cliente-mcp-inspector--claude-desktop)
5. [Las 10 vulnerabilidades (concepto · código · mitigación)](#-las-10-vulnerabilidades)
6. [Defensas transversales](#-defensas-transversales-de-la-charla)
7. [Mapa vulnerabilidad → defensa](#-mapa-vulnerabilidad--defensa)
8. [Cómo extenderlo](#-cómo-extenderlo)

---

## 🎯 Qué incluye

- Un **servidor MCP real** (`server.py`, SDK oficial `mcp` / FastMCP) que expone
  herramientas vulnerables; con `MCP_SECURE=1` registra las versiones seguras.
- **10 módulos** (`mcp_demo/vulns/mcpNN_*.py`), uno por categoría del Top 10. Cada
  módulo contiene **la versión vulnerable y la segura una al lado de la otra**,
  muy comentadas, más un `demo()` que muestra el ataque y su mitigación.
- Un **runner** (`demo.py`) que ejecuta los 10 escenarios *exploit → mitigación*
  en consola, **sin necesidad de un LLM ni de un cliente MCP**.
- **Tests** (`tests/test_mitigations.py`) que prueban, por cada vulnerabilidad,
  que la versión vulnerable es explotable y que la segura la bloquea.

---

## 🚀 Instalación y ejecución rápida

Requiere **Python 3.10+**.

```bash
# 1) (recomendado) entorno virtual
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate

# 2) dependencias
pip install -r requirements.txt

# 3) ejecutar todas las demos exploit -> mitigación
python demo.py

# ...o una sola categoría
python demo.py MCP-3

# 4) tests
pytest -q
```

Salida típica (recortada):

```
MCP-1 · Fuga del contexto de sesión (IDOR)
   Alice crea contexto:         ctx-1
   Mallory pide:                ctx-1
   ❌ VULNERABLE devuelve:      {'iban': 'ES76 ...', 'notas': 'despido confidencial'}
   ✅ SEGURO ante Mallory:      AccessDenied -> contexto no encontrado o sin acceso
```

---

## 🧱 Arquitectura del proyecto

```
mcp-owasp-top10-demo/
├── server.py                 # Servidor MCP (FastMCP). Vulnerable por defecto; MCP_SECURE=1 = seguro
├── demo.py                   # Runner de las 10 demos exploit -> mitigación (sin LLM)
├── requirements.txt
├── pyproject.toml
├── .env.example
├── mcp_demo/
│   ├── common.py             # Datos ficticios, usuarios, secretos falsos, logger de AUDITORÍA, cripto
│   ├── defenses.py           # Human-in-the-loop (#3) y auditoría (#6), transversales
│   └── vulns/
│       ├── mcp01_context_leak.py        # MCP-1  Fuga de contexto de sesión (IDOR)
│       ├── mcp02_context_injection.py   # MCP-2  Inyección de datos contextuales  ← Pydantic
│       ├── mcp03_broken_access.py       # MCP-3  Control de acceso del protocolo roto
│       ├── mcp04_model_state_exposure.py# MCP-4  Exposición del estado del modelo
│       ├── mcp05_insecure_persistence.py# MCP-5  Persistencia insegura del contexto ← cifrado + TTL
│       ├── mcp06_tool_impersonation.py  # MCP-6  Imitación de herramientas / Shadow MCP
│       ├── mcp07_token_theft.py         # MCP-7  Exposición de secretos / robo de tokens ← SecretStr
│       ├── mcp08_rug_pull.py            # MCP-8  Rug Pull (retirada de confianza)
│       ├── mcp09_dow_dos.py             # MCP-9  Denegación de cartera/servicio (DoW/DoS)
│       └── mcp10_auth_bypass.py         # MCP-10 Omisión de autenticación ← JWT firmado
└── tests/
    └── test_mitigations.py
```

Cada módulo de `vulns/` sigue el mismo patrón, pensado para leerse en la charla:

```python
# ❌ VERSIÓN VULNERABLE   -> dónde está el fallo, comentado con 💥
def vulnerable_xxx(...): ...

# ✅ VERSIÓN SEGURA       -> la mitigación a nivel de código
def secure_xxx(...): ...

# DEMO: ejecuta el exploit contra la vulnerable y lo bloquea con la segura
def demo(): ...
```

---

## 🔌 Cómo conectarlo a un cliente MCP (Inspector / Claude Desktop)

Es un servidor MCP **de verdad** (transporte *stdio*), así que puedes cargarlo en
cualquier cliente MCP para “tocar” las herramientas en vivo durante la charla.

**MCP Inspector** (UI web oficial para probar servidores):

```bash
npx @modelcontextprotocol/inspector python server.py          # modo vulnerable
MCP_SECURE=1 npx @modelcontextprotocol/inspector python server.py   # modo seguro
```

**Claude Desktop** — añade a `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "owasp-mcp-demo": { "command": "python", "args": ["/ruta/al/server.py"] }
  }
}
```

> Recuerda: arranca en modo **vulnerable** por defecto. Úsalo solo en local.

---

## 🔥 Las 10 vulnerabilidades

Para cada una: **en qué consiste**, **dónde se ve en el código**, **cómo se explota**
y **cómo se mitiga** (conceptual + código). Los fragmentos de código son extractos;
el detalle completo y comentado está en el módulo correspondiente.

---

### MCP-1 · Fuga del contexto de sesión
📄 `mcp_demo/vulns/mcp01_context_leak.py`

**En qué consiste.** Exposición de datos de un usuario a otro no autorizado por una
**gestión incorrecta del identificador de contexto**. En la práctica es un **IDOR**:
si el `context_id` es adivinable y el servidor no comprueba la propiedad, cualquiera
lee el contexto de otro.

**Dónde está el fallo.** Ids **secuenciales** (`ctx-1`, `ctx-2`, …) y una lectura que
**no comprueba quién pide**:

```python
_counter = itertools.count(1)                 # 💥 ids predecibles
def vulnerable_get_context(context_id):
    return _CONTEXTS[context_id].data          # 💥 sin control de propiedad (IDOR)
```

**Exploit.** Alice crea `ctx-1`; Mallory pide `ctx-1` (o enumera ids) y lo lee entero.

**Mitigación — conceptual.** Identificadores **no adivinables** (UUIDv4 /
`secrets.token_urlsafe`), cada contexto **ligado al usuario autenticado** y validado
en cada acceso (mínimo privilegio). *(Defensa #4 de la charla: aislamiento de contexto.)*

**Mitigación — código.**

```python
def next_context_id_secure():
    return f"ctx-{secrets.token_urlsafe(24)}"  # 128+ bits, no enumerable

def secure_get_context(context_id, caller):
    ctx = _CONTEXTS.get(context_id)
    if ctx is None or ctx.owner_user_id != caller:
        raise AccessDenied("contexto no encontrado o sin acceso")  # mensaje genérico
    return ctx.data
```

---

### MCP-2 · Inyección de datos contextuales
📄 `mcp_demo/vulns/mcp02_context_injection.py` — **defensa estrella: Pydantic**

**En qué consiste.** Un atacante inyecta datos maliciosos en la **capa de contexto**
para manipular una decisión posterior (un motor de reglas, una autorización). Es el
primo del *Prompt Injection*, pero sobre los **datos de estado**, no sobre el prompt.

**Dónde está el fallo.** Se fusiona el payload del usuario sobre el estado de decisión
(*mass assignment*):

```python
decision_state.update(user_payload)            # 💥 el usuario sobreescribe la decisión
approved = decision_state["is_admin"] or decision_state["discount"] >= 50
```

**Exploit.** El payload incluye `{"is_admin": true, "discount": 100}` y la decisión se
vuelca a favor del atacante.

**Mitigación — conceptual.** Trata **todo** dato de contexto como **entrada no
confiable**; define un **esquema estricto por herramienta** que **rechaza campos no
declarados**; nunca fusiones datos no confiables sobre las variables de decisión (esas
se calculan en el servidor).

**Mitigación — código (Pydantic con `extra="forbid"`):**

```python
class UserContext(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rechaza is_admin, discount, etc.
    user_id: Annotated[str, Field(min_length=1, max_length=64)]
    amount:  Annotated[int, Field(ge=0, le=100_000)]
    coupon:  Annotated[str, Field(max_length=16, pattern=r"^[A-Z0-9_-]*$")] = ""

ctx = UserContext.model_validate(user_payload)  # falla ruidosamente ante basura
discount = _COUPONS.get(ctx.coupon, 0)          # el descuento lo decide el servidor
```

---

### MCP-3 · Control de acceso del protocolo roto
📄 `mcp_demo/vulns/mcp03_broken_access.py`

**En qué consiste.** No se valida que el servicio que consume el protocolo tenga
autorización para modificar un contexto de **nivel superior**. Un microservicio de
confianza *baja* altera un contexto de confianza *alta*.

**Dónde está el fallo.** Se escribe cualquier campo sin mirar el nivel de confianza
del llamante ni la sensibilidad del campo:

```python
def vulnerable_update_field(field, value, *, caller_trust):
    _HIGH_CTX.data[field] = value              # 💥 'la red interna es de confianza'
```

**Exploit.** Un servicio `trust=10` cambia `approval_level` (sensibilidad 90) de un
contexto `trust=100`.

**Mitigación — conceptual.** **Servicio de autorización centralizado**: define
explícitamente qué servicio/rol puede *crear/leer/actualizar/eliminar* qué campos; el
nivel de confianza del emisor debe **igualar o superar** la sensibilidad del campo
(mínimo privilegio). *(Defensa #5 de la charla.)*

**Mitigación — código (matriz de capacidades):**

```python
FIELD_SENSITIVITY = {"note": 10, "approval_level": 90}

def secure_update_field(field, value, *, caller_trust):
    required = FIELD_SENSITIVITY[field]
    if caller_trust < required:
        raise AuthzError(f"trust {caller_trust} insuficiente para '{field}'")
    _HIGH_CTX.data[field] = value
```

---

### MCP-4 · Exposición del estado del modelo
📄 `mcp_demo/vulns/mcp04_model_state_exposure.py`

**En qué consiste.** Fuga de información sobre **arquitectura, parámetros, system
prompt o datos de entrenamiento** a través de **metadatos**, **respuestas** o **trazas
de error**. Facilita ataques de inferencia o de modelos adversarios.

**Dónde está el fallo.** La respuesta incluye las “tripas” del modelo y, ante un error,
el **stack trace completo**:

```python
return {"score": score, "_debug": {"system_prompt": _SYSTEM_PROMPT,
                                    "model_meta": _MODEL_META}}   # 💥
except Exception:
    return {"error": traceback.format_exc()}                     # 💥 rutas internas
```

**Mitigación — conceptual.** Separa la respuesta pública de los metadatos internos;
**mensajes de error genéricos** con un `error_id` de correlación (el detalle va a logs
internos); nunca expongas system prompt, pesos ni configuración.

**Mitigación — código.**

```python
def secure_infer(text):
    try:
        return {"score": _score(text)}         # solo lo público
    except Exception as exc:
        error_id = uuid.uuid4().hex[:12]
        audit.error("error_id=%s: %r", error_id, exc)   # detalle solo en logs
        return {"error": "error interno", "error_id": error_id}
```

---

### MCP-5 · Persistencia insegura del contexto
📄 `mcp_demo/vulns/mcp05_insecure_persistence.py`

**En qué consiste.** Guardar el **historial de contexto** sin cifrar o con retención
débil. Quien comprometa un backup o un volcado de caché se lleva todo el contexto de
negocio sensible.

**Dónde está el fallo.** Caché en **texto plano** y **sin TTL**:

```python
def store(self, key, value):
    self._data[key] = value                    # 💥 texto plano, sin caducidad
```

**Mitigación — conceptual.** **Cifrado en reposo** de todo almacén de contexto; **TTL
cortos y obligatorios** para contextos sensibles; **revocación** al cerrar sesión o
ante anomalías. *(Defensa #4 de la charla: aislamiento + cifrado.)*

**Mitigación — código (Fernet = AES-128-CBC + HMAC, con TTL):**

```python
class SecureContextStore:
    def __init__(self, key=None, ttl_seconds=300):
        self._fernet = Fernet(key or Fernet.generate_key())
        self._ttl = ttl_seconds
    def store(self, key, value):
        self._blobs[key] = (self._fernet.encrypt(value.encode()), time.time()+self._ttl)
    def retrieve(self, key):
        token, expires = self._blobs[key]
        if time.time() > expires:              # TTL -> se revoca
            del self._blobs[key]; return None
        return self._fernet.decrypt(token).decode()
```

Un volcado del almacén seguro solo revela *ciphertext*.

---

### MCP-6 · Imitación de herramientas / Shadow MCP
📄 `mcp_demo/vulns/mcp06_tool_impersonation.py`

**En qué consiste.** Atacantes crean herramientas MCP **fraudulentas** que imitan
servicios de confianza (nombres/descripciones calcados). *Shadow MCP*: herramientas no
autorizadas que aparecen en el catálogo y el agente invoca creyéndolas legítimas.

**Dónde está el fallo.** El registro resuelve **por nombre**, y el último gana:

```python
def register(self, name, fn, description=""):
    self._tools[name] = fn                     # 💥 un impostor pisa a send_payment
```

**Exploit.** Mallory registra `send_payment` maliciosa; el agente ejecuta la suya.

**Mitigación — conceptual.** **Catálogo gobernado**: *allowlist* de herramientas
aprobadas, **pin por fingerprint/hash** de la definición (+ firma del publicador)
verificado antes de invocar, y **detección proactiva de Shadow MCP** (lo no aprobado
se rechaza).

**Mitigación — código.**

```python
def _fingerprint(name, description):
    return hashlib.sha256(json.dumps({"name":name,"description":description},
                                     sort_keys=True).encode()).hexdigest()

class SecureRegistry:
    def register(self, name, fn, description=""):
        if self._allow.get(name) != _fingerprint(name, description):
            raise ShadowToolError(f"'{name}' no aprobada (Shadow MCP)")
        self._tools[name] = fn
```

---

### MCP-7 · Exposición de datos sensibles / robo de tokens
📄 `mcp_demo/vulns/mcp07_token_theft.py`

**En qué consiste.** Entornos mal configurados exponen **claves API, tokens y
credenciales** en respuestas, logs o mensajes de error.

**Dónde está el fallo.** Se devuelven y se loguean los secretos tal cual:

```python
return {"stripe_api_key": FAKE_SECRETS["STRIPE_API_KEY"], ...}   # 💥 en la respuesta
line = f"token={token}"                                          # 💥 secreto en el log
```

**Mitigación — conceptual.** Los secretos **nunca** salen en respuestas ni logs;
gestión con un *secret manager*; **tokens de alcance mínimo y vida corta**; redacción
en logs. En código, `SecretStr` de Pydantic evita volcarlos por accidente.

**Mitigación — código.**

```python
class AppConfig(BaseModel):
    stripe_api_key: SecretStr                  # repr/dict lo enmascaran: '**********'
    db_password:    SecretStr
    region: str

def secure_get_config():
    return {"region": _CONFIG.region, "has_stripe_key": True}    # metadatos, no valores
def secure_log_request(token):
    audit.info("token=%s", redact(token))      # ••••••••••3456
```

---

### MCP-8 · Rug Pull (retirada de confianza)
📄 `mcp_demo/vulns/mcp08_rug_pull.py`

**En qué consiste.** Una herramienta parece legítima, gana adopción y **de repente
cambia su comportamiento/definición** para robar datos o causar daño.

**Dónde está el fallo.** La herramienta es mutable y se ejecuta “lo que haya ahora”:

```python
def rug_pull(self, new_fn, new_desc):
    self.fn = new_fn                           # 💥 cambia en caliente tras ganar confianza
def vulnerable_invoke(tool, *args):
    return tool.fn(*args)
```

**Mitigación — conceptual.** **Pin** de la definición aprobada por **versión + hash**;
cualquier cambio invalida la confianza hasta re-aprobación y re-firma; **monitorización
continua** (auditoría); inmutabilidad de lo aprobado.

**Mitigación — código.**

```python
class PinnedTool:
    def __init__(self, fn, description):
        self._approved_hash = _code_hash(fn, description)   # hash del código+descr
    def invoke(self, *args):
        if _code_hash(self._fn, self._description) != self._approved_hash:
            raise RugPullDetected("la herramienta cambió desde su aprobación")
        return self._fn(*args)
```

---

### MCP-9 · Denegación de cartera/servicio (DoW/DoS)
📄 `mcp_demo/vulns/mcp09_dow_dos.py`

**En qué consiste.** Herramientas maliciosas/comprometidas consumen recursos o abusan
de APIs conectadas: **costes inesperados** (*Denial of Wallet*) o **indisponibilidad**
de servicios críticos.

**Dónde está el fallo.** Llamadas a una “API de pago” **sin tope** de número ni de
presupuesto:

```python
def vulnerable_bulk_enrich(n, api):
    for i in range(n):
        api.enrich(f"rec-{i}")                 # 💥 sin límite de llamadas ni de coste
```

**Exploit.** Un lote de 10.000 cuesta 100 € en una sola invocación.

**Mitigación — conceptual.** **Límites de recursos** (nº de llamadas, **presupuesto por
sesión**, *timeouts*), **rate limiting** por usuario/herramienta y *circuit breakers*
en las APIs aguas abajo. *(Defensa #2 de la charla: sandboxing + límites.)*

**Mitigación — código.**

```python
class BudgetGuard:
    def __init__(self, max_calls=100, max_cost=1.0, max_seconds=2.0): ...
    def run(self, n, api):
        if n > self.max_calls: raise QuotaExceeded(...)
        for i in range(n):
            if api.cost + COST_PER_CALL > self.max_cost: raise QuotaExceeded(...)
            if time.time()-start > self.max_seconds:      raise QuotaExceeded("timeout")
            api.enrich(f"rec-{i}")
```

---

### MCP-10 · Omisión de autenticación (Authentication Bypass)
📄 `mcp_demo/vulns/mcp10_auth_bypass.py`

**En qué consiste.** Mecanismos de autenticación débiles o mal aplicados permiten
**eludir los controles** y suplantar usuarios/servidores.

**Dónde está el fallo.** El servidor **confía en lo que dice el cliente** (y tiene un
*backdoor* de debug):

```python
if request.get("debug"): return "ADMIN (debug)"             # 💥 backdoor
if request.get("role") == "admin": return "ADMIN"           # 💥 claim del cliente
```

**Exploit.** Mallory manda `{"role": "admin"}` o `{"debug": true}` y ejecuta la acción.

**Mitigación — conceptual.** El rol **nunca** viaja en el payload: se deriva de un
**token firmado y verificado** en el servidor (JWT HS256/RS256); sin *backdoors*;
verificación en cada microservicio. *(Defensa #5: control de acceso centralizado.)*

**Mitigación — código (PyJWT):**

```python
def issue_token(user_id):                      # el IdP firma con el rol REAL
    u = USERS[user_id]
    return jwt.encode({"sub": u.user_id, "role": u.role, "exp": ...}, JWT_SECRET, "HS256")

def secure_admin_action(token):
    claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # verifica firma
    if claims.get("role") != "admin":
        raise AuthError("se requiere rol admin")                 # rol del claim, no del body
```

Un token **forjado** sin la clave de firma es rechazado automáticamente.

---

## 🧰 Defensas transversales de la charla

Además de las mitigaciones por vulnerabilidad, dos defensas aplican a varias y están
en `mcp_demo/defenses.py` y `mcp_demo/common.py`:

- **Human-in-the-loop (defensa #3)** — `defenses.guard_action()`: clasifica las acciones
  por riesgo y **exige confirmación humana explícita** para las irreversibles
  (`send_payment`, `delete_data`, `send_email`, `wire_transfer`). En `server.py`, la
  herramienta `send_payment` solo se ejecuta con `human_approved=True`.
- **Auditoría continua (defensa #6)** — logger `audit` de `common.py`: cada ruta segura
  deja traza de **quién hizo qué, cuándo y con qué contexto**, para trazabilidad y
  detección de anomalías.

Y la **validación con Pydantic** (defensa #1) aparece en MCP-2 (`extra="forbid"`) y
MCP-7 (`SecretStr`) como ejemplos canónicos.

---

## 🗺️ Mapa vulnerabilidad → defensa

| Vulnerabilidad | Archivo | Defensa principal |
|---|---|---|
| **MCP-1** Fuga de contexto de sesión | `mcp01_context_leak.py` | IDs no adivinables + propiedad (aislamiento) |
| **MCP-2** Inyección de datos contextuales | `mcp02_context_injection.py` | **Pydantic** `extra="forbid"` |
| **MCP-3** Control de acceso del protocolo roto | `mcp03_broken_access.py` | Autorización centralizada (matriz de capacidades) |
| **MCP-4** Exposición del estado del modelo | `mcp04_model_state_exposure.py` | Errores genéricos + no exponer metadatos |
| **MCP-5** Persistencia insegura del contexto | `mcp05_insecure_persistence.py` | Cifrado en reposo (Fernet) + TTL |
| **MCP-6** Imitación / Shadow MCP | `mcp06_tool_impersonation.py` | Allowlist + fingerprint de la definición |
| **MCP-7** Exposición de secretos / robo de tokens | `mcp07_token_theft.py` | `SecretStr` + redacción en logs |
| **MCP-8** Rug Pull | `mcp08_rug_pull.py` | Pin por hash + re-verificación en cada llamada |
| **MCP-9** DoW/DoS | `mcp09_dow_dos.py` | Límites de recursos/presupuesto + timeouts |
| **MCP-10** Omisión de autenticación | `mcp10_auth_bypass.py` | JWT firmado + rol del claim |
| *(transversal)* acciones críticas | `defenses.py` | Human-in-the-loop |
| *(transversal)* trazabilidad | `common.py` | Auditoría continua |

---

## 🧩 Cómo extenderlo

- **Añadir un escenario**: crea `mcp_demo/vulns/mcpNN_*.py` con `vulnerable_*`,
  `secure_*` y `demo()`, y regístralo en `mcp_demo/vulns/__init__.py` (`CATALOG`).
- **Exponerlo como herramienta MCP**: añade un `@mcp.tool()` en `server.py` que
  conmute vulnerable/seguro según `SECURE`.
- **Probarlo**: añade un test en `tests/test_mitigations.py` (vulnerable explotable +
  segura bloquea).

---

## 📚 Referencias

- OWASP MCP Top 10 — <https://owasp.org/www-project-mcp-top-10>
- Model Context Protocol — <https://modelcontextprotocol.io>
- Anthropic · MCP — <https://www.anthropic.com/news/model-context-protocol>
- MCP Attack Matrix (Akto) — <https://www.akto.io/mcp-attack-matrix>

> Verifica siempre la lista oficial del OWASP MCP Top 10 al preparar la charla: el
> catálogo evoluciona y los nombres/orden de las categorías pueden cambiar.

---

*Material formativo · BIT UP 2026 · «Seguridad en Agentes de IA · MCP».*
