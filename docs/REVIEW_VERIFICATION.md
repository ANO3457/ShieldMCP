# Reviewer preparation verification — October 11, 2026

This is author-run verification, not independent red-teaming or production validation. The prerelease target commit contains this preparation; raw framework outputs are in `eval/results/review_2026_10_11/`.

| Check | Observed result |
|---|---|
| Full unit/regression suite | 119 passed |
| Trained Stage 1 / Stage 3 models | Both loaded and predicted offline |
| Actual newline-framed subprocess stdio call | Blocked call returned a JSON-RPC error to client and exited cleanly on EOF |
| Content-Length subprocess demo | Benign response passed; metadata poisoning filtered; injected response returned error |
| Classifier eval with missing weights | Refused to run; no mislabeled fallback result |
| Synthetic dataset reproduction | All 7 release input files exactly match public generators' default output |
| Release assets | SHA-256 checksums verified |

| Framework backend | Detected / 487 fixed attacks | Missed | Benign passed / 200 |
|---|---|---|---|
| Heuristic | 445 | 42 | 190 |
| Classifier | 487 | 0 | 190 |
| Tiered | 469 | 18 | 190 |

These are detector verdicts on the shipped synthetic scenarios. They do not measure an autonomous agent completing attacks or legitimate tasks; framework “attack_succeeded” fields are historical detector-miss proxies. Classifier splits share templates and exact examples. See `models/README.md` for provenance and generalization limits.

Verified runtime: Python 3.12.13, mcp 1.28.1, torch 2.13.0, transformers 5.13.0, accelerate 1.14.0, pytest 9.1.1. Core checks used the existing local environment; a clean dependency installation, external LLM providers, live Ollama console run, hosted SSE endpoint, deployment and production workload were not tested in this preparation.

Known boundaries: Streamable HTTP is absent; governance and cache APIs require explicit integration. Unknown tools called before inventory validation receive parameter checks only. Known Stage 1 blocked/quarantined tools are rejected on direct calls; approval requires registry authorization and clean inventory revalidation. Stage 3 cannot reverse a tool side effect.
