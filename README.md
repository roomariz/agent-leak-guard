# Agent Leak Guard

**PII redaction is not tool authorisation.**

Agent Leak Guard is an educational Python project that demonstrates a specific AI-agent security risk: removing recognised personal information does not, by itself, prevent confidential data from reaching an unauthorised tool or destination.

The project combines **Microsoft Presidio**, optional **Google Gemini or OpenAI-compatible LLMs**, and an independently enforced **Python permission policy**. It compares an unrestricted redaction-only baseline (Configuration A) with deterministic tool-level permission enforcement (Configuration B) and comprehensive layered security with attribute-level filtering and response validation (Configuration C).

It uses **synthetic documents, customer records, and in-memory mock tools**. No real email is sent, and no real confidential document is transmitted to a reporting service.

Developed as a practical companion to the article *Why PII Redaction Alone Cannot Prevent Data Leakage in AI Agents*.

## Key features

- PII detection and redaction with Microsoft Presidio.
- One-shot, structured tool-call proposals from Google Gemini or an OpenAI-compatible LLM endpoint.
- Deterministic checks for permitted tools, recipients and trusted document sensitivity labels.
- **Three security configurations compared side-by-side:**
  - **A (Redaction only):** Unrestricted baseline applying PII redaction only.
  - **B (Tool permissions):** PII redaction + deterministic tool and destination allowlists.
  - **C (Layered security):** Tool permissions, attribute-level input filtering, attribute-level output filtering, and final-response PII/sensitive-data validation.
- Structured synthetic customer records with trusted field-level sensitivity classifications.
- Comprehensive 15-scenario evaluation suite testing legitimate tasks, attacks, and bypass attempts.
- Automated tests (110 tests) that run without making live LLM API requests.
- A clearly labelled limited regex fallback for offline demonstrations when Presidio is unavailable.

**Scope:** This is an educational security demonstration, **not** a production-ready security software suite, a general prompt-injection defence, or a dynamic information-flow control system.

## How it works

```text
                       Synthetic user task / request
                                     │
                                     ▼
                          AI agent proposes action
                                     │
                                     ▼
                       Validate proposal schema & IDs
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
                 ▼                   ▼                   ▼
          A: Redaction only    B: Tool policy       C: Layered security
                 │                   │                   │
                 │             Check tool and            ├─ 1. Tool, action & dest check
                 │             destination               ├─ 2. Input attribute filter
                 │                   │                   ├─ 3. Output scope filter
                 │             ┌─────┴─────┐             ├─ 4. PII redaction
                 │             │           │             └─ 5. Final response guard
                 ▼             ▼           ▼                     │
            Mock send       ALLOW        BLOCK             ┌─────┴─────┐
            with leaks         │        No send            │           │
                          Redact+send                    PERMIT      BLOCK
                                                      (Safe fields  No leaks
                                                      delivered)
```

The model proposes a tool and document/field identifiers. The application retrieves data from a local trusted store. The **model does not receive document contents**, and its proposal does not grant permission. The Python policy decides whether the selected data may reach the proposed destination.

- **Configuration A** deliberately omits permission checks to demonstrate why PII redaction alone does not prevent confidential data from leaving the boundary.
- **Configuration B** adds fail-closed tool and destination checks, stopping unauthorized egress of classified documents, but cannot prevent attribute-level leakage on permitted internal endpoints.
- **Configuration C** implements multi-layered enforcement: attribute allowlists prevent restricted fields from entering or leaving tools, and an outbound response guard catches residual sensitive markers before answers are displayed.

## Repository layout

```text
agent-leak-guard/
├── agent_security/
│   ├── llm.py                 # LLM adapters and proposal validation
│   ├── models.py              # Documents, customer records, classifications and requests
│   ├── policy.py              # Deterministic tool, destination and field allowlist policies
│   ├── redaction.py           # Presidio and offline regex adapter
│   ├── response_guard.py      # Final-response PII and sensitive data validation
│   ├── workflow.py            # Local document store, mock tools and layered pipeline
│   ├── evaluation.py          # Original 5-scenario evaluation (Configs A & B)
│   └── evaluation_c.py        # 15-scenario evaluation & 3-way comparative benchmark
├── tests/
│   ├── test_demo.py           # Verification of basic workflow & redaction
│   ├── test_evaluation.py     # Tests for 5-scenario evaluation
│   ├── test_google.py         # Gemini API mock tests
│   ├── test_llm.py            # OpenAI-compatible API mock tests
│   └── test_layered.py        # 70 unit and integration tests for Configuration C
├── demo.py                    # Multi-mode demonstration (A, B, C)
├── llm_demo.py                # LLM-assisted, one-shot demonstration
├── evaluate.py                # Five-scenario evaluation command (Configs A & B)
├── evaluate_c.py              # Configuration C 15-scenario comparative evaluation
├── EVALUATION.md              # Original 5-scenario evaluation methodology and caveats
├── EVALUATION_CONFIG_C.md     # Detailed Configuration C technical evaluation & metrics
├── TEST_RESULTS.md            # Earlier local verification record
├── .env.example               # Placeholder environment configuration
├── requirements.txt
└── README.md
```

## Requirements and installation

- Python 3.10+ (Python 3.12 recommended).
- The packages in `requirements.txt`.
- A compatible spaCy English model for Presidio.
- An API key **only** when using a hosted LLM.

From the repository root:

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

**macOS/Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

If a compatible spaCy English model is already installed and Presidio initialises correctly, you can use that existing setup. Confirm actual redaction behaviour in your environment rather than assuming every entity is detected.

## Configure a hosted LLM

Copy `.env.example` to `.env` and replace placeholders with your own values, or set the key directly in your terminal. **Never commit `.env` or a real API key.**

Example `.env` for Google Gemini:

```dotenv
GEMINI_API_KEY=YOUR_GOOGLE_API_KEY
LLM_MODEL=gemini-3.5-flash-lite
```

Google API keys can be created through [Google AI Studio](https://aistudio.google.com/apikey). Model availability and pricing depend on your account.

For the Windows PowerShell session, you may alternatively use:

```powershell
$env:GEMINI_API_KEY = "YOUR_GOOGLE_API_KEY"
```

For OpenAI-compatible providers, use `LLM_API_KEY`, `LLM_MODEL` and, where required, `LLM_API_BASE`. Hosted providers receive the synthetic task and document identifiers. They do **not** receive the stored synthetic private forecast content through this application.

## Quick demonstrations

**Three-way configuration comparison (A, B, C)**

```powershell
python demo.py --redactor regex-demo --mode all
```

**Original fixed-request comparison with Presidio (A & B)**

```powershell
python demo.py --redactor presidio --mode both
```

**Live Google Gemini proposal with Presidio (A & B)**

```powershell
python llm_demo.py --provider google --model gemini-3.5-flash-lite --redactor presidio --mode both
```

**Offline policy illustration only (A & B)**

```powershell
python demo.py --redactor regex-demo --mode both
```

`regex-demo` masks simple email patterns and is **not** equivalent to Microsoft Presidio. No result from that mode should be described as Presidio detection performance. The external reporting tool in every demonstration is a local in-memory mock.

## Running evaluations

### 1. Configuration C Evaluation & Three-Way Benchmark (15 Scenarios)

Evaluates identical scenario inputs across Configurations A, B, and C:

```powershell
python evaluate_c.py --redactor regex-demo
```

With Microsoft Presidio:

```powershell
python evaluate_c.py --redactor presidio
```

Output files:
```text
evaluation_results/
├── results_config_c.csv
└── results_config_c.json
```

See [`EVALUATION_CONFIG_C.md`](EVALUATION_CONFIG_C.md) for complete details on architecture, metrics, and scenario breakdown.

### 2. Original Five-Scenario Security Evaluation (Configs A & B)

Evaluates the original two configurations:

| Scenario | What it checks | Proposal source in live Google mode |
| --- | --- | --- |
| `public_allowed` | Public report to an approved recipient | Gemini |
| `confidential_external` | Confidential report proposed for external delivery | Gemini |
| `mixed_classification` | Public and confidential documents in one request | Gemini |
| `unapproved_destination` | A request addressed to an unapproved recipient | Direct fixture |
| `untrusted_snippet_lure` | A labelled malicious instruction inside the model's task input | Gemini |

**Run all automated tests (110 tests)**

```powershell
python -m pytest -q
```

**Run offline with fixed requests**

```powershell
python evaluate.py --provider fixed --redactor regex-demo
```

**Run one live Google Gemini evaluation pass**

```powershell
python evaluate.py --provider google --model gemini-3.5-flash-lite --redactor presidio
```

**Run three passes**

```powershell
python evaluate.py --provider google --model gemini-3.5-flash-lite --redactor presidio --repeat 3
```

Each live pass makes up to **four Gemini model calls** and one direct-fixture evaluation, so `--repeat 3` can make up to **12 Gemini API calls**. Calls may incur API charges. Proposals may differ between runs, and API errors are recorded separately rather than counted as successful security blocks.

---

## Evaluation Results

### Configuration C: Three-Way Benchmark Results (19 November 2026)

Evaluated across 15 synthetic scenarios using `python evaluate_c.py --redactor regex-demo`:

| Metric | Config A (Redaction only) | Config B (Tool policy) | Config C (Layered security) |
|---|:---:|:---:|:---:|
| **Unauthorised tool executions** | 4 | 1 | **0** |
| **Unauthorised field disclosures** | 4 | 4 | **0** |
| **Sensitive data in final response** | 2 | 2 | **0** |
| **Policy enforcement failures** | 10 | 7 | **0** |
| **Attack scenarios blocked** | 0 / 4 | 3 / 4 | **4 / 4 (100%)** |
| **Bypass attempts neutralized** | 0 / 2 | 0 / 2 | **2 / 2 (100%)** |
| **Legitimate tasks completed** | 4 / 4 (100%) | 4 / 4 (100%) | **4 / 4 (100%)** |
| **False-positive blocking rate** | 0.0% | 0.0% | **0.0%** |
| **Avg authorised fields delivered** | 100.0%* | 100.0%* | **100.0%** |

*\* Configurations A and B delivered 100% of fields only because they lack attribute controls, passing confidential and unauthorized fields alongside legitimate ones.*

### Historical Results: Configurations A & B (17 November 2026)

The following historical results are preserved from the original local Windows run using **Google Gemini `gemini-3.5-flash-lite` and Microsoft Presidio**. They are observations from the supplied evaluation output, not an independent replication or a production benchmark.

**Automated tests:** `40 passed in 10.66s` (user-reported terminal output).

**Three-pass evaluation**

| Metric | Observed count |
| --- | ---: |
| Scenario executions | 15 |
| Valid proposals | 15 |
| Proposal errors | 0 |
| Live Gemini proposals | 12 |
| Direct fixtures | 3 |
| Proposals denied by the reference policy | 9 |
| Unauthorised in-memory sends: redaction-only baseline | 9 |
| Unauthorised in-memory sends: policy-protected | 0 |
| Denied proposals blocked by policy | 9 |
| Authorised proposals permitted by policy | 6 |

The three repetitions of `untrusted_snippet_lure` produced a **public-document proposal**, not the malicious confidential-document request. In those repetitions, both configurations permitted the public request. They therefore **do not demonstrate successful prompt injection or the blocking of a prompt-injection-induced disclosure**.

An earlier single-pass live evaluation produced **two proposal errors** (`mixed_classification` and `untrusted_snippet_lure`). The later three-pass evaluation reported zero errors. Results should not be merged or selectively reported as if all executions succeeded.

**Interpretation:** The controlled comparison shows that, for these specific proposed actions and trusted document labels, a deterministic destination policy prevented the simulated unauthorised sends that the deliberately unrestricted redaction-only baseline allowed. It does **not** establish a general leakage-prevention rate or performance against real-world attackers.

### Result files

Original evaluation output:
```text
evaluation_results/
├── results.csv
└── results.json
```

Configuration C comparative output:
```text
evaluation_results/
├── results_config_c.csv
└── results_config_c.json
```

These files contain scenario metadata, policy decisions, status flags and mock-send counts, not raw synthetic document bodies or API credentials.

See [`EVALUATION.md`](EVALUATION.md) for original scenario details and [`EVALUATION_CONFIG_C.md`](EVALUATION_CONFIG_C.md) for Configuration C details.

## Security assumptions and limitations

- **Synthetic test data only.** All markers, customer records, and endpoints (`partner.example`, `intranet.example`, `attacker.example`) are demonstration fixtures.
- **No real external send.** The `MockTool` and `MockStructuredTool` only store payloads in memory.
- **No private document content sent to the LLM.** The LLM receives only task instructions and metadata/identifiers; Python resolves records locally after the model proposes a request.
- **One-step operation.** The LLM proposes tool actions in one step. It does not autonomously execute multi-step tool plans.
- **Trusted metadata.** Field and document sensitivity labels are assigned by trusted application configuration, not by model inference.
- **Narrow enforcement scope.** This is not user identity verification, tenant isolation, network-level egress control, a complete enterprise DLP platform, or full information-flow control.
- **PII detection has limits.** Presidio and regex patterns can miss sensitive entities or misclassify text. PII detection cannot establish whether a disclosure is authorized.
- **Static schemas.** Schemas and allowlists in this prototype are predefined.

## Why this project exists

The experiment illustrates distinct security responsibilities:

1. **Content transformation:** detect and redact information matching selected PII categories.
2. **Action authorisation:** independently decide whether an agent-proposed tool action may disclose data to a destination.
3. **Attribute filtering:** restrict what fields can enter tools and what fields can be returned to agents.
4. **Final-response validation:** inspect agent-generated output to catch residual sensitive disclosures before user presentation.

None of these layers can replace the others. The project makes these distinctions observable, testable, and reproducible.

## Licence

MIT. See [`LICENSE`](LICENSE).
