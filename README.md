# INTCOMP-CryptoRisk# INTCOMP CryptoRisk

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![Tests](https://img.shields.io/badge/tests-34%20reported-brightgreen)
![Status](https://img.shields.io/badge/release-Final%20Tournament-6f42c1)

**Autor:** Juan Felipe Vásquez · INTCOMP

Deterministic decision platform for **cryptographic / post-quantum migration under constraints and dependencies**.

```
CORE DECIDES · EVALUATOR SCORES · AI EXPLAINS · AUDIT PROVES
```

CryptoRisk is **not** a chatbot, **not** a game, and **not** only a risk dashboard.  
It turns a cryptographic estate inventory into a **reproducible, auditable migration decision**.

**Highest risk ≠ automatically first migration step.** Dependencies and policies constrain order.

## Architecture

```
CSV → Inventory → Core (risk, dependencies, policies, stress)
    → Decision → Audit → optional AI explanation
```

Tournament (separate):

```
Frozen Case → Participant (Bearer) → Submission → Evaluator (C1–C6) → Score → Leaderboard → Audit
```

Browser → FastAPI → `runtime_INTCOMP-V41` Core. Frontend does not recalculate Core scores or decisions.

## Install & run

**Windows:** extract → double-click `START_INTCOMP.bat` → http://127.0.0.1:8000  

**Linux/macOS:**

```bash
python3 -m pip install -r requirements.txt
python3 launcher.py
```

## Tests

```bash
PYTHONPATH=runtime_INTCOMP-V41:.:backend python -m pytest tests/ -q
# Expected: 34 passed
```

## Analysis flow

1. Start with **NO INVENTORY LOADED** (demo is **not** auto-loaded)  
2. **Upload CSV** or optional **Demo Dataset**  
3. **Inventory** · **Risk** · **Dependencies**  
4. **Decision** — stress test → **Core decision**  
5. **Audit** · **Executive report** (`GET /api/executive-report`)  
6. AI may explain; **AI authority = NONE**

### CSV schema (required)

`asset_id`, `name`, `algorithm`, `key_size`, `protocol`, `criticality`, `internet_exposed`, `data_lifetime_years`, `dependencies`  

Optional: `migration_status`, `aliases`  
Template: `GET /api/inventory/template.csv`

### Risk

Heuristic prioritization signal from the Core. **Not** a probability of compromise or attack.

### Decision

UI separates **CORE DECISION** from **AI EXPLANATION**. Client cannot inject severity, sequence, or decision.

## Tournament

Independent of the Analysis upload session. Uses **Case V0** (payment migration) and a **deterministic evaluator**.

Benchmarks (must remain):

| Submission style | Score |
|---|---:|
| PERFECT | 100.0 |
| SWAP | 75.0 |
| REVERSE | 65.0 |
| RISK ONLY | 48.5 |
| EMPTY | 0.0 |

Auth: `Authorization: Bearer <token>` (server-generated). `X-Participant-Id` is **not** authority. Score is **server-side only**.

## AI

`get_default_ai_client()`: NVIDIA if `NVIDIA_API_KEY` is set and client initializes; otherwise **Fallback**.  
Never claim NVIDIA connected without a key. AI does not change severity, sequence, decision, or Tournament score.

## Security model (closed demo)

Bearer isolation, anti-score-injection, no Core decision from the client.  
**Not** claimed: enterprise multi-tenant production security or internet-scale anti-cheat.

## Integrity

| Item | Value |
|---|---|
| Core package SHA-256 | `06f703f59549e3c5ed17eecaddf9ea0d4124518b53ca27d7c7f9155964101427` |
| Core / evaluator / Case V0 | **Frozen** |
| Tests | **34 passed** |

See `RELEASE_MANIFEST.md`.

## Known limitations

- Closed demo / jury lab  
- In-memory Analysis session  
- NVIDIA live path needs API key  
- Browser UI E2E not fully automated  
- No enterprise multi-tenancy / full anti-cheat claims  
- Risk scores are **not** financial ROI or attack probabilities  

## Release lineage

- RC reference: `CRYPTORISK-V4.7-TOURNAMENT-RC.zip`  
  SHA-256: `40e4d02833b524dca5ac4bdbbe243065d5ec554d2d6460b24f2ccdcc83642836`
