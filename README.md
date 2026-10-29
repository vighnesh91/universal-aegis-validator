# Universal AegisValidator

[![Python Version](https://shields.io)](https://python.org)
[![License](https://shields.io)](LICENSE)
[![Build Status](https://shields.io)]()

**Universal AegisValidator (UAV)** is a production-ready, standard-library-only security orchestration framework engineered to audit AI application endpoints for guardrail compliance, adversarial robustness, and behavioral regression. 

By executing a versioned corpus of defensive tests using multi-strategy mutation composition, UAV evaluates the target's compliance against explicit, operator-configured expectations. The entire lifecycle—from structured mutation and boundary assessment to SIEM logging and true PDF 1.4 binary report compilation—requires **zero third-party dependencies**.

---

## 🔒 Scope & Authorized Use Notice

> [!IMPORTANT]
> **AegisValidator is designed strictly for defensive security validation.**
> Live assessment modes require explicit targeting authorization (`--authorize-target`). The framework enforces active defense boundaries including Server-Side Request Forgery (SSRF) filters, absolute redirect rejections, loopback isolation blocks, and cloud-metadata isolation. Never target endpoints you do not own or possess explicit written authorization to test.

---

## ✨ Core Architectures & Capabilities

* 📦 **Zero-Dependency Topology:** Pure Python (>= 3.9 up to 3.13). No `ReportLab`, `WeasyPrint`, `requests`, or `pydantic`. Fully air-gapped pipeline capability.
* 🛡️ **Multi-Turn & Structural Mutation:** Composition-based injection engine supporting 17 adversarial strategies (Base64 framing, NFKC/NFD scripts, zero-width space segmentation, context sentence shuffling).
* 📐 **Deterministic Outcome Engine:** Categorizes behaviors into exactly four mathematical states: `PASS`, `FAIL`, `INCONCLUSIVE`, and `ERROR` using token Jaccard and character 3-gram distance matrices.
* 📑 **Hardened PDF 1.4 Writer:** Compiles colorful, pixel-accurate executive summaries, dashboard vector graphs, and detailed evidence blocks natively from byte streams.
* 🤖 **Inert Tool Execution Sandbox:** Integrates a capability-free capability sandbox to safely log, filter, and review model-generated tool call triggers without process escalation or host injection risk.
* 🏭 **SecOps & CI/CD Native:** Includes deployment gate evaluation policies, automated webhook routing (Slack, MS Teams, Splunk HEC), and standard logging layers (CEF, LEEF, ECS) for direct SIEM ingestion.

---

## 🚀 Quick Start

### 1. Zero-Credential Offline Simulation Audit
Verify the engine, test evaluation paths, and view a sample PDF/JSON report artifact compiled fully offline:
```bash
python3 universal_aegis_validator.py --mode simulate
```

### 2. Run the Internal Test Suite
Run the built-in, structural unit tests covering endpoints, extractors, signers, and mathematical formulas:
```bash
python3 universal_aegis_validator.py --run-tests
```

### 3. Inspect Provider Integration Profiles
View the out-of-the-box structural templates for OpenAI, Anthropic Messages, Google Gemini, Ollama, vLLM, and enterprise custom configurations:
```bash
python3 universal_aegis_validator.py --list-profiles
```

### 4. Authorized Live Security Assessment
Execute a live assessment against a verified corporate endpoint:
```bash
export AEGIS_OPENAI_API_KEY="sk-prod-..."
python3 universal_aegis_validator.py --mode live \
    --profile openai_chat \
    --authorize-target https://openai.com \
    --model gpt-4o-mini \
    --max-tests 12 --budget 24
```

### 5. Local Interactive Workspace UI
Spin up the embedded, loopback-locked developer web interface to control evaluations and manage automatic PDF layout downloads locally:
```bash
python3 universal_aegis_validator.py --web --web-port 8765
```

---

## ⚙️ Automated Pipeline CI/CD Gate Integration

UAV exposes rigorous exit-code contracts to drop builds directly inside enterprise workflows based on custom risk profiles:

| Exit Code | Classification | Meaning / Context |
| :--- | :--- | :--- |
| `0` | `EXIT_OK` | Assessment completed; all gate thresholds passed smoothly. |
| `1` | `EXIT_GATE_FAILED` | Conformance breach; behavioral finding violated policy threshold. |
| `2` | `EXIT_CONFIG_ERROR` | Runtime execution flags or profile schema are unparseable. |
| `3` | `EXIT_REFUSED` | SSRF alert or target authentication mismatch triggered a block. |
| `5` | `EXIT_INFRA_FAILED` | Endpoint unavailability or timeouts breached `--max-errors`. |

### Example Pipeline Trigger:
```bash
python3 universal_aegis_validator.py --mode live \
    --profile enterprise_custom \
    --authorize-target https://example.corp \
    --gate --min-pass-rate 0.95 \
    --max-fail-severity "critical=0,high=1" \
    --audit-log ./logs/siem_intake.json --audit-log-format ecs
```

---

## 📊 Scoring Formularies & Integrity Metrics

AegisValidator rejects opaque security representations. Every metric is explicitly defined and recorded in the JSON evidence payload:

* **Behavioral Pass Rate:** $\frac{\text{PASS}}{\text{PASS} + \text{FAIL}}$ (Excludes `ERROR` infrastructure timeouts and `INCONCLUSIVE` structural drifts from the denominator).
* **Transformation Consistency:** Measures the token alignment stability of surface-preserving mutations against the unmutated baseline (Threshold: $\text{Jaccard} \ge 0.30$).
* **Statistical Uncertainty:** Applies the Wilson Score Interval model to proportions; intervals are safely withheld for small populations ($n < 5$) to bound false precision.
