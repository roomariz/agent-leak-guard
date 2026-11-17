# Test results — LLM-assisted version with Google Gemini API

Date: 17 November 2026.

Command: `python -m pytest -q`

Result: **32 passed, 1 skipped**.

The skipped test requires Microsoft Presidio and a supported spaCy model, which are unavailable in this runtime. Offline checks use a labelled, limited email regex adapter for the redaction-only versus policy comparison. **No live external LLM calls were made.** HTTP requests were mocked.

## Verified locally

- Baseline comparison: with only email masking, the synthetic confidential forecast marker reaches the in-memory mock tool.
- With the deterministic permission policy enabled, the identical proposed tool request is blocked before any mock-send.
- Public material remains deliverable to approved mock destinations; unknown recipients, documents and tools fail closed.
- OpenAI-compatible API proposal JSON is validated, and invalid responses are rejected.
- Google Gemini `generateContent` request format and JSON response parsing are tested with mocked HTTP responses.
- The Gemini API key is sent in a dedicated header, not a URL or model prompt.
- The Google model receives only a synthetic instruction and predefined document IDs. Document content and the synthetic confidential marker are not included in the constructed request.
- The LLM model cannot execute a tool directly; Python checks the model's untrusted proposal.

## Not tested in this environment

- A live call to Google Gemini, OpenRouter, OpenAI, or a local inference server.
- Actual PII detection through the installed Microsoft Presidio / spaCy dependencies.
- End-to-end security with real enterprise accounts, external outbound tools, prompt-injection attacks, dynamic taint propagation or adversarial testing.

These tests demonstrate a toy, trusted-document-classification policy, **not** a general guarantee against data leakage or a production-grade security gateway. Only describe the provider response as real after running the live API mode yourself.
