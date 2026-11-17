# Agent Leak Guard

**PII redaction is not tool authorisation.**

Agent Leak Guard is an educational Python project that demonstrates a specific AI-agent security risk: removing recognised personal information does not, by itself, prevent confidential data from reaching an unauthorised tool or destination.

The project combines **Microsoft Presidio**, optional **Google Gemini or OpenAI-compatible LLMs**, and an independently enforced **Python permission policy**. It compares a deliberately unrestricted, redaction-only baseline with a policy-protected configuration using the **same proposed tool request**.

It uses **synthetic documents and in-memory mock tools**. No real email is sent, and no real confidential document is transmitted to a reporting service.

Developed as a practical companion to the article *Why PII Redaction Alone Cannot Prevent Data Leakage in AI Agents*.

## Key features

- PII detection and redaction with Microsoft Presidio.
- One-shot, structured tool-call proposals from Google Gemini or an OpenAI-compatible LLM endpoint.
- Deterministic checks for permitted tools, recipients and trusted document sensitivity labels.
- Side-by-side comparison of redaction-only and redaction-plus-policy execution.
- Five controlled evaluation scenarios, including an illustrative malicious-instruction lure.
- Repeated evaluations with metadata-only CSV and JSON output.
- Automated tests that run without making live LLM API requests.
- A clearly labelled limited regex fallback for offline demonstrations when Presidio is unavailable.

**Scope:** This is a single-step LLM-assisted tool-request demonstration, **not** a fully autonomous agent, a general prompt-injection defence, or an implementation of dynamic information-flow control.

## How it works

```text
                       Synthetic user task
                               |
                               v
                      LLM proposes tool call
                      (or fixed test fixture)
                               |
                               v
                     Validate proposed schema
                               |
                               v
                  Retrieve trusted document labels
                               |
                +--------------+---------------+
                |                              |
                v                              v
         A: Redaction only              B: Redaction + policy
                |                              |
         Presidio redaction          Check tool, destination
                |                    and source classification
                |                              |
                v                       +------+------+
         In-memory mock                 |             |
         send can occur               ALLOW         BLOCK
                                          |             |
                                   Redact + mock    No mock send
                                       send
```

The model proposes a tool and document identifiers. The application retrieves data from a local trusted store. The **model does not receive document contents**, and its proposal does not grant permission. The Python policy decides whether the selected data may reach the proposed destination.

The baseline deliberately omits the destination/classification check to demonstrate why PII redaction alone does not enforce authorisation.

## Repository layout

```text
agent-leak-guard/
├── agent_security/
│   ├── llm.py                 # LLM adapters and proposal validation
│   ├── models.py              # Documents, classifications and tool requests
│   ├── policy.py              # Deterministic authorisation check
│   ├── redaction.py           # Presidio and offline regex adapter
│   ├── workflow.py            # Local document store and mock tool execution
│   └── evaluation.py          # Scenario definitions, metrics and result export
├── tests/                     # Automated tests, including evaluation tests
├── demo.py                    # Fixed-request demonstration
├── llm_demo.py                # LLM-assisted, one-shot demonstration
├── evaluate.py                # Five-scenario evaluation command
├── EVALUATION.md              # Detailed evaluation methodology and caveats
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

**Fixed-request comparison with Presidio**

```powershell
python demo.py --redactor presidio --mode both
```

**Live Google Gemini proposal with Presidio**

```powershell
python llm_demo.py --provider google --model gemini-3.5-flash-lite --redactor presidio --mode both
```

**OpenAI-compatible provider (example: OpenRouter)**

```powershell
python llm_demo.py --provider openai-compatible --api-base https://openrouter.ai/api/v1 --model YOUR_MODEL_ID --redactor presidio --mode both
```

**Offline policy illustration only**

```powershell
python demo.py --redactor regex-demo --mode both
```

`regex-demo` masks simple email patterns and is **not** equivalent to Microsoft Presidio. No result from that mode should be described as Presidio detection performance.

The external reporting tool in every demonstration is a local in-memory mock.

## Five-scenario security evaluation

Run the included suite to evaluate the same proposed tool request with and without deterministic authorisation.

| Scenario | What it checks | Proposal source in live Google mode |
| --- | --- | --- |
| `public_allowed` | Public report to an approved recipient | Gemini |
| `confidential_external` | Confidential report proposed for external delivery | Gemini |
| `mixed_classification` | Public and confidential documents in one request | Gemini |
| `unapproved_destination` | A request addressed to an unapproved recipient | Direct fixture |
| `untrusted_snippet_lure` | A labelled malicious instruction inside the model's task input | Gemini |

The unapproved-destination scenario uses a **direct fixture** because the existing model-response validator does not accept recipients outside its preconfigured set.

The malicious-snippet case is a **toy instruction-lure test**. It does not retrieve an actual GitHub issue or run a real MCP or RAG workflow. Do not describe it as a confirmed prompt-injection exploit.

**Run all automated tests**

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

### Results: 17 November 2026

The following results were reported from a local Windows run using **Google Gemini `gemini-3.5-flash-lite` and Microsoft Presidio**. They are observations from the supplied evaluation output, not an independent replication or a production benchmark.

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

Evaluation output is written to:

```text
evaluation_results/
├── results.csv
└── results.json
```

These files contain scenario metadata, policy decisions, status flags and mock-send counts, not raw synthetic document bodies or API credentials. Review the files before publishing. Each invocation writes to the same output filenames, so preserve a copy if you need to retain results from multiple runs. The latest three-pass results should be distinguished from the earlier one-pass results.

See [`EVALUATION.md`](EVALUATION.md) for full scenario definitions and limitations.

## Security assumptions and limitations

- **Synthetic test data only.** The marker `FORECAST-SECRET-2030` is fictional. `partner.example`, `intranet.example` and `attacker.example` are demonstration destinations, not real endpoints contacted by the application.
- **No real external send.** The `MockTool` only stores the simulated payload in memory.
- **No private document content sent to the LLM.** The selected provider receives the synthetic task and predefined document IDs; Python resolves the document locally after the model proposes a request.
- **One-step operation.** The LLM proposes a single tool action. It does not autonomously retrieve data or execute multi-step tool plans.
- **Trusted metadata.** Document sensitivity labels are assigned by the local store and assumed correct. The policy does not dynamically track provenance or determine whether arbitrary unlabelled text is confidential.
- **Narrow enforcement scope.** This is not user identity verification, tenant isolation, real network egress control, a complete data-loss-prevention platform or full information-flow control.
- **PII detection has limits.** Presidio can miss sensitive entities or misclassify text. The observed removal of a synthetic email does not measure overall precision or recall.
- **Limited attack testing.** The labelled malicious snippet is supplied as part of the model's task input, not a separate lower-trust retrieved tool result; it is not a realistic end-to-end prompt-injection benchmark.

A production application would need identity-bound permissions, trusted classification, validation of actual tool arguments, destination controls, isolation, appropriate logging, monitoring and additional adversarial testing.

## Why this project exists

The experiment illustrates two different security responsibilities:

1. **Content transformation:** detect and redact information matching selected PII categories.
2. **Action authorisation:** independently decide whether an agent-proposed tool action may disclose the selected data to the selected destination.

The second responsibility cannot be inferred from whether the first succeeded. The project is intended to make that difference reproducible and observable, while clearly documenting the boundaries of the demonstration.

## Licence

MIT. See [`LICENSE`](LICENSE).
