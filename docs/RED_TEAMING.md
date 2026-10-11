# Independent review and red-teaming

ShieldMCP welcomes independent evaluation. This guide proposes a reproducible review; it does not represent an agreed partnership or an external validation result.

## Review entry points

- `src/shieldmcp/proxy/`: actual stdio and legacy SSE interception.
- `src/shieldmcp/core/pipeline.py`: metadata, argument and response checks.
- `src/shieldmcp/stage1/`, `stage2/`, `stage3/`: detector implementations.
- `src/shieldmcp/governance/`: experimental opt-in scope, pinning, failure policy and cache APIs.
- `models/README.md`: trained artifacts, provenance and limitations.
- `eval/`: synthetic adversarial/benign servers, scenarios and benchmark drivers.

Run `pytest -q` and `python examples/live_proxy_demo.py` after the README installation. Run the framework evaluation into a fresh output directory. Load trained artifacts before selecting classifier or tiered backends; verify the loader did not fall back to heuristics.

## Attack → defend → verify

1. Freeze agent/model versions, tool inventory, permissions, task definition, ShieldMCP commit/configuration and model checksums. Use synthetic records and controlled side-effect sinks.
2. Run the same agent/tasks with protection disabled, heuristic protection, classifier protection, and tiered protection. State whether optional governance APIs were separately integrated.
3. Have the external evaluator own unseen attacks. Include metadata poisoning, tool/schema changes, response injection, cross-tool chaining, paraphrases, multilingual/encoded payloads, content beyond the 512-token classifier window, concurrency, failures and realistic benign instructions.
4. Define success by observable effects: unauthorized destination/action or canary reaching a controlled sink. Keep detector warnings, blocked attempts, attempted actions and completed side effects separate. A response block cannot reverse a completed tool action.
5. Report denominators, repetitions/seeds, attack completion rate, benign task completion, false positive/negative rates, p50/p95 added latency and failure/degradation behavior. Publish unfavorable outcomes and residual risks alongside fixes.
6. Retest fixes on independently held-out cases. Attribute findings to the evaluator and preserve versioned reproduction instructions where disclosure is appropriate.

## Optional integration pilot

A first integration can wrap an existing MCP stdio server without changing its implementation, or use the Python pipeline around the tool boundary. A separate trace bridge can associate metadata-only verdicts with an existing tool-call trace: stage, action, threat family, opaque server/tool identifier, commit/model version and latency. Confirm the receiving product's supported API and ingestion behavior before calling it a working adapter. Raw prompts, responses, arguments and alert details can contain sensitive data; choose a deliberate redaction/export policy.

A successful small pilot should produce an independently reproducible before/after result and a decision on continued integration. Product adoption, a case study, attribution or a partner endorsement should only be recorded after the organization actually agrees and uses the work.
