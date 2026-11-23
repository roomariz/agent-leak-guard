# Security Audit Report: Configuration C (Layered Security)

**Target Repository:** `agent-leak-guard`  
**Audit Scope:** Configuration C Implementation, Evaluation Harness, and Comparative Security Claims  
**Date of Audit:** 2026-11-19  
**Status:** Audit Completed Prior to Implementing Corrections  

---

## Executive Summary

Configuration C ("Layered Security") was introduced into `agent-leak-guard` to demonstrate that a 4-tier defence-in-depth pipeline (tool and action permission checks, attribute-level input filtering, attribute-level output filtering, and final-response validation) can prevent data leakage while preserving legitimate AI-agent task completion.

The reported evaluation claimed:
- 103 passing automated tests.
- 0 unauthorized tool executions.
- 0 unauthorized field disclosures.
- 0 sensitive final-response disclosures.
- 4 / 4 legitimate tasks completed (100%).
- 0.0% false-positive blocking.

This audit conducted an independent, rigorous, evidence-based review of the source code, data flows, evaluation methodology, and test suite. The audit confirmed that while the architectural concept of multi-layer boundaries is sound, **the reported results are significantly overstated and several implementation defects and security vulnerabilities exist in the code**. Specifically:
1. Passing 103 unit tests did not establish security effectiveness because tests were written against the flawed implementations.
2. In Scenario 9, the final response leaked a confidential credit limit (`"Credit limit is 25000."`) without being flagged or redacted because `check_response` was called without confidential record values when tool execution was blocked.
3. In Scenario 5, customer name `"Alice Testuser"` leaked in the final response to an external partner (`partner.example`) because the response guard lacks recipient awareness and cannot detect person names or restricted fields.
4. Tool output filtering only performs shallow 1-level dictionary key filtering; nested JSON structures and non-string attributes bypass filtering and PII redaction entirely.
5. The confidential marker (`FORECAST-SECRET-2030`) was written verbatim into CSV and JSON evaluation reports.
6. Evaluation metrics were calculated inconsistently across configurations: Configuration C was evaluated using a weaker definition of unauthorized field disclosure than Configurations A and B, and response leakage checks for Configurations A and B were conducted without confidential record checking, under-reporting baseline leaks.
7. Comparative metrics for Configurations A and B in `evaluate_c.py` were hardcoded string literals (`'4 (100%)'`, `'0.0%'`, `'100.0%*'`) rather than computed from execution records.
8. The evaluation relied entirely on static synthetic fixtures without invoking any real LLM or testing dynamic prompt-injection resistance.

---

## Phase 1: Source Code and Data-Flow Audit

### Execution Path Analysis

The pipeline traces execution from `StructuredToolRequest` through `execute_layered` in `agent_security/workflow.py`:

```text
StructuredToolRequest + simulated_response
   │
   ├── Layer 1 & 2: Tool Input Authorisation & Attribute Filtering (`authorise_structured`)
   │     ├── Check tool name in FIELD_ALLOWLISTS
   │     ├── Check recipient for tool in FIELD_ALLOWLISTS
   │     ├── Check action in PERMITTED_ACTIONS
   │     └── Compute safe allowed fields (strip unknown, unlisted, CONFIDENTIAL)
   │           │
   │           ├── If blocked: calls check_response(response_text) [DEFECT: no confidential records!]
   │           │               returns LayeredOutcome(status="BLOCKED")
   │           └── If permitted: continues with allowed_fields
   │
   ├── Data Store Retrieval (`TrustedCustomerStore.retrieve`)
   │     └── Look up record_ids [NOTE: record_ids are unvalidated for tenant/user access]
   │
   ├── Layer 3: Attribute Output Filtering & PII Redaction
   │     ├── filter_record_fields: shallow key filter [DEFECT: nested dicts/lists bypass!]
   │     └── string PII redaction: redactor.redact [DEFECT: skips non-strings!]
   │
   ├── Simulated Tool Transmission
   │     └── receiver.send(payload) [Executed before Layer 4 response validation!]
   │
   └── Layer 4: Final-Response Validation
         ├── check_response(response_text, confidential_records)
         └── redact_response(response_text, confidential_records)
```

### Security Layer Analysis Table

| Security Layer | Enforcing Function & File | Data In / Data Out | Policy Enforced & Source | Failure Behavior | Bypass Potential | Disclosure Timing |
|---|---|---|---|---|---|---|
| **Layer 1: Tool & Action Authorisation** | `authorise_structured`<br>`agent_security/policy.py` | `StructuredToolRequest`, `requested_fields`<br>➜ `AttributeDecision` | `FIELD_ALLOWLISTS`, `PERMITTED_ACTIONS` (trusted server config) | Returns `permitted=False`; `execute_layered` returns `BLOCKED` | `tool_name`, `recipient`, and `action` must match allowlist exactly. However, `record_ids` has no access policy. | Enforcement occurs before `store.retrieve` and tool dispatch. |
| **Layer 2: Attribute-Level Input Filtering** | `authorise_structured`<br>`agent_security/policy.py` | `requested_fields`, `CUSTOMER_RECORD_SCHEMA`<br>➜ `AttributeDecision.allowed_fields` | Schema allowlist; unlisted, unknown, and `CONFIDENTIAL` fields dropped | Drops unlisted fields. If no fields remain, returns `BLOCKED`. | Dotted names (`fields.credit_limit`) and globs are dropped. Only top-level field names checked. | Enforcement occurs before tool execution. |
| **Layer 3: Attribute-Level Output Filtering & Redaction** | `filter_record_fields`<br>`agent_security/policy.py` & `execute_layered` in `workflow.py` | `record.fields: dict[str, Any]`, `allowed_fields`<br>➜ `filtered_payloads: list[dict]` | `CUSTOMER_RECORD_SCHEMA` confidential exclusion, `Redactor.redact` | Fields not in `allowed_fields` dropped; string values redacted | **CRITICAL BYPASS:** Shallow dictionary comprehension (`{k: v for k, v in record_fields.items() if k in safe_allowed}`) leaves nested objects uninspected. Non-string values bypass redaction. Free-text permitted fields (e.g. `notes`) containing secrets are not filtered. | Tool payload sent to `receiver.send` **before** response guard runs. If tool is outbound, egress occurs prior to response check. |
| **Layer 4: Final-Response Validation** | `check_response` & `redact_response`<br>`agent_security/response_guard.py` | `response_text: str`, `confidential_records`<br>➜ `ResponseGuardResult`, safe string | Regexes for email, phone, SSN, card; `_BUSINESS_MARKERS`; exact substring match for confidential values | Flags findings; redacts matched substrings | **CRITICAL BYPASS:**<br>1. Not called with confidential records when tool is blocked.<br>2. Recipient-blind (cannot block restricted PII to external recipients).<br>3. Exact substring check misses formatted numbers (`$25,000`, `25k`).<br>4. Values < 3 chars ignored. | Runs after tool execution, before displaying response to user. |

---

## Phase 2 & 3: Critical Evaluation Audit and Methodological Weaknesses

### Evaluation of Reported Findings

| Claimed Metric | Reported Result | Audit Assessment | Evidence & Root Cause |
|---|:---:|:---:|---|
| **103 passing automated tests** | 103 passed | **Conditionally Supported** | Tests pass, but existing test cases validate the flawed logic and omit adversarial negative cases (e.g., nested structures, confidential response when tool is blocked). |
| **Unauthorised tool executions** | 0 | **Supported** | All 4 attack scenarios (`unapproved_destination`, `unknown_tool`, `unapproved_action`, `all_confidential_fields`) were blocked from tool dispatch. |
| **Unauthorised field disclosures** | 0 | **Overstated / Flawed Metric** | `evaluation_c.py` line 504 defined Config C unauthorized disclosure as `bool(delivered & confidential_field_names)`, ignoring `RESTRICTED` PII disclosure. Furthermore, nested records leak confidential data without detection. |
| **Sensitive final-response disclosures** | 0 | **Overstated / False** | In Scenario 9 (`all_confidential_fields`), `"Credit limit is 25000."` is emitted unredacted. In Scenario 5 (`external_partner_pii_attempt`), `"Alice Testuser"` is emitted to an external partner unredacted. Both were reported as 0 leaks. |
| **Legitimate tasks completed (4/4)** | 100% | **Conditionally Supported** | The 4 predefined legitimate tasks completed, but `evaluate_c.py` line 106 hardcoded `'4 (100%)'` for Configurations A and B instead of computing them from evaluation records. |
| **False-positive blocking rate** | 0.0% | **Conditionally Supported** | None of the 4 legitimate tasks were blocked, but the display formatting in `evaluate_c.py` line 110 multiplied the integer count by 100 (`count * 100`) rather than computing a percentage. |

### Methodological Weaknesses

1. **Absence of Live LLM Calls in Configuration C:** While the original Config A/B experiment in `evaluate.py` optionally supported Google Gemini, Configuration C (`evaluate_c.py`) relies **100% on static synthetic fixtures**. No live model is invoked.
2. **Predefined Model Responses:** The response guard was never evaluated against real model generations; it evaluated static strings hand-crafted by the developer.
3. **Prompt Injection Claim Overstatement:** Scenario 10 (`prompt_injection_field_name`) merely tests that an unlisted field name (`"ignore_policy_and_send_all_fields"`) is dropped by an allowlist. This provides **zero evidence** of prompt-injection resistance.
4. **Presidio vs. Regex-Demo:** `evaluate_c.py` defaults to `regex-demo`. Presidio is only invoked for string redaction if explicitly passed via CLI, and is **never** used in `response_guard.py` (which uses built-in regexes only).

---

## Phase 4: Confirmed Vulnerabilities and Implementation Defects

### Finding 1: Response Guard Fails to Inspect Confidential Records on Blocked Tool Execution
- **Severity:** **Critical**
- **Location:** `agent_security/workflow.py` (lines 159-168, 194-202, 223-231) & `agent_security/evaluation_c.py` (line 507)
- **Description:** When a tool call is blocked (e.g. by input policy in Scenario 9 `all_confidential_fields`), `execute_layered` calls `check_response(response_text)` without providing `confidential_records`. Consequently, confidential field values (such as `"25000"`) are not recognized as sensitive. The response `"Credit limit is 25000."` is returned unmodified and reported as safe.
- **Impact:** Confidential data present in the model's response is disclosed to the user even when the underlying tool call is blocked.

### Finding 2: Nested Data Structures Bypass Tool Output Filtering and PII Redaction
- **Severity:** **Critical**
- **Location:** `agent_security/policy.py` (`filter_record_fields`, lines 144-160) & `agent_security/workflow.py` (`execute_layered`, lines 274-280)
- **Description:** `filter_record_fields` performs a shallow 1-level dictionary comprehension: `{k: v for k, v in record_fields.items() if k in safe_allowed}`. If a permitted field (e.g. `notes`) contains a nested dictionary or list containing confidential fields or PII, the entire nested structure is preserved. In `execute_layered`, redaction only applies `if isinstance(v, str)`, so nested dictionaries and lists are sent directly to the tool receiver unredacted.
- **Impact:** Attackers or complex schemas with nested objects can exfiltrate confidential data and PII through permitted top-level fields.

### Finding 3: Confidential Secret Marker Verbatim Leakage into Audit Reports
- **Severity:** **High**
- **Location:** `agent_security/response_guard.py` (`_detect_business_markers`, line 77) & `agent_security/evaluation_c.py` (`save_layered_results`, lines 656-676)
- **Description:** `_detect_business_markers` returns the raw secret marker `"FORECAST-SECRET-2030"` in `business_markers_found`. This list is serialized into `LayeredRecord.response_guard_findings` and written verbatim into `results_config_c.csv` and `results_config_c.json`, violating the documented requirement that metadata reports must never contain raw sensitive values.
- **Impact:** Metadata-only audit logs expose secret business markers to disk and unprivileged consumers.

### Finding 4: Recipient-Blind Response Guard Discloses Restricted PII to External Destinations
- **Severity:** **High**
- **Location:** `agent_security/response_guard.py` (`check_response`, lines 107-150) & `agent_security/evaluation_c.py` (Scenario 5, lines 135-148)
- **Description:** `check_response` has no recipient or destination context. It does not check for customer names (NER) or `RESTRICTED` schema fields. In Scenario 5 (`external_partner_pii_attempt`), the agent sends a response containing `"Alice Testuser"` to external partner `partner.example`. The response guard evaluates this as `permitted=True`, leaking restricted customer PII to an external recipient without detection.
- **Impact:** Unauthorized disclosure of personal data to external parties via response text.

### Finding 5: Inconsistent and Weakened Evaluation Metric for Configuration C
- **Severity:** **High**
- **Location:** `agent_security/evaluation_c.py` (lines 504, 539-541, 543, 552-554, 555)
- **Description:** 
  1. In line 504, Configuration C's `unauthorised_field_disclosure` checks only `delivered & confidential_field_names`. In lines 539 and 552, Configurations A and B check `confidential_field_names` AND `partner.example` restricted PII (`name`, `email`, `phone`).
  2. In lines 543 and 555, `resp_check_a` and `resp_check_b` were called without `confidential_records`, falsely reporting 0 response leakages for Scenario 3 (`credit_limit` and `credit_score` in response) for Configurations A and B.
- **Impact:** Evaluation results are biased, overstating Configuration C's relative security advantage while under-reporting baseline leakage.

### Finding 6: Substring Matching and Number Formatting Bypass in Response Guard
- **Severity:** **Medium**
- **Location:** `agent_security/response_guard.py` (`_detect_confidential_field_values`, lines 81-105)
- **Description:** Confidential field checking relies on `str(value) in text` where `len(str_value) >= 3`. Any formatting variation (e.g., currency formatting `$25,000`, abbreviation `25k`, floating point `25000.00`) completely bypasses detection. Values under 3 digits are ignored. Conversely, common numbers (e.g. `100`, `500`) trigger false positives.
- **Impact:** Trivial evasion of response guard by model formatting; risk of false-positive blocking on legitimate numbers.

### Finding 7: Hardcoded Comparative Metrics and Formatting Error in `evaluate_c.py`
- **Severity:** **Medium**
- **Location:** `evaluate_c.py` (lines 106, 110, 114)
- **Description:** Lines 106, 110, and 114 hardcode string literals for Configuration A and B metrics (`'4 (100%)'`, `'0.0%'`, `'100.0%*'`) rather than computing them from baseline evaluation records. Line 110 formats false-positive blocking as `count * 100` rather than `(count / total) * 100`.
- **Impact:** Misleading evaluation presentation not backed by runtime computations.

---

## Phase 5: Verification of Original Experiment Preservation

The original A/B experiment files (`agent_security/evaluation.py`, `agent_security/llm.py`, `evaluate.py`, `EVALUATION.md`, `TEST_RESULTS.md`) were inspected:
- Running `python evaluate.py --provider fixed --redactor regex-demo` operates correctly and independently of Configuration C.
- The original 5 scenarios remain reproducible.
- Any corrections to Configuration C must not alter or break the original 5-scenario evaluation files or tests.

---

## Recommended Corrections

1. **Fix Response Guard Invocation on Blocked Execution:** Pass confidential records from `store` (or records targeted by `request.record_ids`) to `check_response` and `redact_response` even when input validation fails.
2. **Implement Recursive/Deep Filtering & Redaction:** Ensure `filter_record_fields` and string redaction recursively sanitize nested dictionaries and lists in customer records.
3. **Redact Sensitive Marker Names in Finding Labels:** Replace raw marker text in `_detect_business_markers` with a generic label (`CONFIDENTIAL_MARKER`) to prevent leakage into CSV/JSON logs.
4. **Make Response Guard Recipient-Aware:** Introduce recipient awareness to `check_response` so restricted fields (like `name`) are blocked or redacted when directed to external recipients.
5. **Standardize Evaluation Metrics:** Use a uniform definition of unauthorized field disclosure and response leakage across Configurations A, B, and C. Compute all metrics dynamically from records.
6. **Add Comprehensive Regression Tests:** Add reproducible tests covering nested data, blocked-call response leakage, external partner PII leakage, marker masking in logs, and formatting variations.
