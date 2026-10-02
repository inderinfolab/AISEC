# AI Security Labs (Streamlit)

Two integrated lab tracks for the *Enterprise AI Security for Architects* course. Everything runs on deterministic,
rule-based simulations: **no API keys, no network, no real exploits.**

1. **Course labs 0-14**: one per course module (Helios case study).
2. **NexaGuard field exercises (34 labs, 4 parts)**: modelled on the structure, scenarios and scoring formulas of the
   open-source companion repo [PacktPublishing/AI-Under-Attack](https://github.com/PacktPublishing/AI-Under-Attack) (MIT).
   Each exercise has: Scenario & tasks, interactive Lab, Hints, Knowledge check, and a "Go deeper" pointer to the
   matching real-tool exercise (Ollama, Promptfoo, Garak, LLM Guard, ModelScan, Checkov, Kubesec, pip-audit...).

## Run
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Test (109 tests: engine logic + every lab rendered and exercised through Streamlit's AppTest)
```bash
pip install -r requirements-dev.txt
pytest -q
```

## Field exercises
| Part | Exercises |
|---|---|
| 1 Foundations | 1.2 Predictability gap, 1.3 Black box, 2.1 Threat model, 3.1 Attack surface, 4.1 Input validation, 4.2 Gateway/WAF/token limits, 4.3 Circuit breakers |
| 2 Attacks | 6.1 Infinite input space, 6.2 Indirect injection & targeted exfil, 6.3 Jailbreaks/Crescendo, 8.1 RAG poisoning before/after, 8.2 RAG monitoring, 10.1 Attack-chain forensics + detection rules, 10.3 Multi-agent cascade, 11.1 Model scanning, 11.2 Backdoor trigger testing, 11.3 Vetting gate, 12.1 Garak-style scan, 12.2 Adaptive red team, 12.3 Composite risk score + OWASP/ATLAS mapping + stakeholder reports |
| 3 Defenses | 14.1 Layered input validation, 14.2 Output sanitisation, 14.3 Tool parameter validation, 15.1 Prompt hardening & tuning, 16.1 Guardrail ensembles, 16.3 Human escalation, 17.1 Supply chain + SBOM, 17.3 Tenant isolation, 18.1 Zero trust (Rule of Two, capability tokens), 18.2 Design patterns, 18.3 Architecture validation |
| 4 Cloud & MLOps | 20.1 Terraform audit/fix, 20.2 Kubernetes hardening, 20.3 ML pipeline audit |

## Files
`app.py` shell and navigation | `labs.py`, `engine.py` course labs 0-14 | `range_core.py` exercise framework |
`ex_part1..4.py` exercise UIs | `ng.py`, `defenses.py`, `infra.py` simulation logic | `tests/`

## Caveats
- Simulations teach principles and relative effects; they do not measure a real model. Swap a live model in behind `ng.run` for that.
- CVE entries, OWASP/ATLAS identifiers and severity bands follow the companion repo's exercises and are simplified; verify against current sources (NVD, pip-audit, OWASP, MITRE ATLAS) before relying on them.
- The pickle sample is only ever scanned statically, never loaded.
