# PII Redaction Is Not Tool Authorisation

A reproducible educational Python project demonstrating why PII redaction alone cannot prevent confidential data leakage through AI-agent tools.

Developed to accompany the LinkedIn article *Why PII Redaction Alone Cannot Prevent Data Leakage in AI Agents*.

## What it does

- Uses synthetic documents stored locally with trusted document-level sensitivity classifications.
- Uses Microsoft Presidio to detect and redact personal information.
- Integrates Google Gemini, OpenRouter, OpenAI-compatible APIs and compatible local LLM endpoints.
- Allows an LLM to propose a structured tool request without providing it with confidential document contents.
- Validates the model's proposed request in Python before executing a mock tool.
- Compares two configurations using the same proposed action: PII redaction alone and PII redaction with deterministic permission enforcement.
- Demonstrates how confidential non-PII information can remain after successful PII redaction.
- Blocks unauthorised disclosure of classified documents through a deterministic tool-permission policy.
- Uses in-memory mock tools, so no real emails or confidential documents are sent to external reporting services.

The project includes a fixed-request demonstration (`demo.py`) and an LLM-integrated demonstration (`llm_demo.py`).

The fixed-request demonstration can run offline after installation. The LLM-integrated demonstration requires an API connection unless a compatible local model server is used.

## Setup (Python 3.10+; Python 3.12 recommended)

```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

## Environment configuration

The project supports API credentials through a local `.env` file.

Create a file named `.env` in the project root:

```dotenv
GEMINI_API_KEY=YOUR_GOOGLE_API_KEY
LLM_MODEL=gemini-3.5-flash-lite

# Optional: OpenAI-compatible provider
LLM_API_KEY=YOUR_OPENAI_COMPATIBLE_KEY
LLM_API_BASE=https://openrouter.ai/api/v1
```

Install `python-dotenv` and ensure `llm_demo.py` loads the environment file before reading API configuration.

The `.env` file must remain private. It is excluded from version control through `.gitignore`.

Use `.env.example` with placeholder values when sharing the project publicly.

### Google Gemini

Run:

```bash
python llm_demo.py --provider google --redactor presidio --mode both
```

The model identifier is loaded from `LLM_MODEL`. Alternatively, specify it explicitly using `--model`.

### OpenAI-compatible providers

Run:

```bash
python llm_demo.py --provider openai-compatible --redactor presidio --mode both
```

The API base and model can be configured through environment variables or command-line arguments.

**Security note:** Hosted LLM providers receive the synthetic task and permitted document identifiers. Confidential document contents remain local. External reporting and intranet tools are simulated entirely in memory.

## Run the real Presidio demo

```bash
python demo.py --redactor presidio --mode both
python -m pytest -q
```

If you cannot install Presidio, the following **limited regex demo** can verify the policy behaviour using simple email masking. It is **not Presidio** and not a PII benchmark:

```bash
python demo.py --redactor regex-demo --mode both
python -m pytest -q
```

Expected shape (output is from the mock receiver only):

```text
A: redaction only
  status: SIMULATED_SEND
  simulated sends: 1
  original email still present: False
  confidential marker still present: True

B: redaction + independent policy
  status: BLOCKED
  simulated sends: 0

Control: public summary to approved partner: SIMULATED_SEND
```

## What this proves, and what it does not

This is a **controlled contrast**, not a production benchmark or evidence of zero leaks. The baseline deliberately lacks a confidentiality policy; the second configuration applies one. The code demonstrates that redacting recognised PII is a separate security property from deciding whether a destination may receive classified information. The marker `FORECAST-SECRET-2030` is artificial, not a secret. The addresses `partner.example` and `intranet.example` are symbolic and never contacted.

The permission gate does **not** implement dynamic information-flow control. It uses server-trusted **document-level classification**, so it cannot identify secrets in unlabelled text, enforce row/field-level policies, trace transformations, handle adversarial plugin code, or establish user authentication. The demonstration assumes these labels and the configured allowlist are trustworthy. An actual agent would require identity-bound permissions, trusted metadata, egress controls, isolation, threat modelling and further adversarial testing. Presidio also has false positives and false negatives, and cannot guarantee identification of all sensitive information.

## Implementation and evaluation status

The prototype has been executed successfully using a live Google Gemini API connection and Microsoft Presidio.

In the observed demonstration, Gemini proposed an `external_report` tool request involving the synthetic `private_forecast` document.

Two configurations were evaluated using the same model-proposed request.

**Configuration A: Redaction only**

- The original email address was absent from the mock-tool payload.
- The synthetic confidential marker remained present.
- The mock tool recorded one simulated send.

**Configuration B: Redaction with deterministic permission enforcement**

- The proposed action was rejected because classified source information was not permitted to use `external_report`.
- The mock tool recorded zero sends.

These observations demonstrate the distinction between PII redaction and tool-level authorisation.

The demonstration uses synthetic information and in-memory tools. It does not transmit confidential documents to actual external services.

The application is a single-step, LLM-assisted tool-request workflow, not a fully autonomous, multi-step agent.

The permission gate uses trusted document-level sensitivity labels. It does not implement general dynamic information-flow control, semantic classification of arbitrary confidential data, or comprehensive prompt-injection protection.

These results represent a controlled demonstration, not a production security benchmark. They do not establish universal protection against data leakage.

## Test coverage

`tests/test_demo.py` checks redaction-only disclosure, blocking, public allow, mixed-classification block, destination and tool default-deny, permitted internal flow, unknown/empty documents, and optional Presidio integration.

## Licence

MIT. Educational use; no customer or personal data is included.

## NEW: Let a real LLM propose the tool call

`llm_demo.py` uses an **OpenAI-compatible Chat Completions endpoint**, so it can work with OpenAI, OpenRouter, or compatible local endpoints. It sends **only synthetic document IDs and a demonstration instruction** to the selected provider. The model NEVER sees document contents, email addresses, or the confidential marker. The model's JSON response is untrusted: Python validates it, retrieves trusted document classifications, and applies the same policy as the original demo.

For a hosted endpoint, set `LLM_API_KEY` in your terminal (do **not** commit it or paste it in the article). Example using OpenRouter:

```bash
# macOS/Linux
export LLM_API_KEY="YOUR_KEY"
python llm_demo.py --api-base https://openrouter.ai/api/v1 --model YOUR_MODEL_ID --redactor presidio --mode both
```

Windows PowerShell:

```powershell
$env:LLM_API_KEY = "YOUR_KEY"
python llm_demo.py --api-base https://openrouter.ai/api/v1 --model YOUR_MODEL_ID --redactor presidio --mode both
```

For a local OpenAI-compatible server, use a localhost API base (for instance `http://localhost:11434/v1` with a compatible installed model). No paid API is needed for that option. The server must support OpenAI-style `/chat/completions`.

```bash
python llm_demo.py --api-base http://localhost:11434/v1 --model YOUR_LOCAL_MODEL --redactor presidio --mode both
```

**Limitations and interpretation**:

- The model proposes one structured tool request; it does **not** read private documents, run tools or autonomously plan multi-step actions. It is a real LLM-assisted tool-request workflow, not a full autonomous agent.
- Both scenarios reuse the *same* model-proposed request so any difference is attributable to the deterministic permission gate.
- The model may choose a safer tool or public document. In that event the contrast will not reproduce the confidential disclosure; report the actual outcome rather than forcing a claimed success.
- The external report/intranet destinations are local `MockTool` objects and never make network calls. **The LLM provider does receive the synthetic task and metadata.** Use a local compatible server if you want to avoid that transfer.
- The policy operates on trusted document classifications. It is not full dynamic information-flow control or a general prompt-injection defence.
- `--redactor regex-demo` is a deliberately limited offline fallback and is not a substitute for Presidio.

Run `python -m pytest -q` to execute the added tests, including mocked API response parsing and fail-closed input validation.


## Google Gemini API (native Google endpoint)

The project now also supports **Google's Gemini API directly**. It uses the
`generateContent` REST endpoint through Python's standard library, so no extra
SDK or additional pip package is required. The model only proposes a tool call:
it does **not** receive the confidential document content or execute the tool.
The existing Python permission gate is unchanged.

Create an API key through [Google AI Studio](https://aistudio.google.com/apikey).
Never paste the key into your code or Git repository. Google Gemini API calls
may incur usage charges depending on your account and model.

**Windows PowerShell:**

```powershell
$env:GEMINI_API_KEY = "YOUR_GOOGLE_API_KEY"
python llm_demo.py --provider google --model gemini-2.5-flash --redactor presidio --mode both
```

**macOS/Linux:**

```bash
export GEMINI_API_KEY="YOUR_GOOGLE_API_KEY"
python llm_demo.py --provider google --model gemini-2.5-flash --redactor presidio --mode both
```

The example model identifier is illustrative; select a model available for your
account. `GOOGLE_API_KEY` is also accepted as an environment-variable alias.
`--api-base` is used only for the OpenAI-compatible provider and is not used for
Google's fixed HTTPS endpoint. To run without Presidio for an *offline policy*
check, replace `--redactor presidio` with `--redactor regex-demo` (not a real
PII detection benchmark).

Google official documentation: [Generate content](https://ai.google.dev/api/generate-content).
Google currently describes `generateContent` as a legacy API relative to the
newer Interactions API, but documents it and its JSON-output configuration.
This integration can be migrated to Interactions in future if needed.

**Security / testing limits:** All actual external-report calls are simulated
with `MockTool`; the Google model call is the only network request. No genuine
Gemini calls have been made as part of the included automated tests. A
successful live run is required before describing real Gemini behaviour in a
published article.
