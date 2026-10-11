# ShieldMCP

**Open-source runtime security for Model Context Protocol (MCP) tool interactions.**

ShieldMCP validates tool metadata, outbound arguments, and inbound responses between an agent and an MCP server. It runs as a stdio or legacy SSE proxy, or as an asynchronous Python pipeline. Apache-2.0; Python 3.11+. This is an alpha research framework; deployment behavior should be tested against your own agent, tools, and workload.

## Start here

```bash
git clone https://github.com/saurabh-yergattikar/ShieldMCP.git
cd ShieldMCP
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Interactive pipeline demo: http://127.0.0.1:8000
shieldmcp demo
```

The default heuristic backend needs no model downloads or API keys. The browser demo computes pipeline verdicts live against curated scenarios and user inputs; it is not a live agent benchmark. For subprocess traffic through the actual stdio proxy:

```bash
python examples/live_proxy_demo.py
```

For an independent review, start with [the red-team guide](docs/RED_TEAMING.md), [model setup and limitations](models/README.md), and the [framework evaluation](eval/run_evaluation.py).

## Architecture

```text
Agent --tools/list--> [Stage 1: metadata integrity] --> MCP server
Agent --tools/call--> [Stage 2: argument checks]    --> MCP server
Agent <--response--- [Stage 3: response analysis]  <-- MCP server
```

| Stage | Checks | Threats addressed |
|---|---|---|
| 1: Description integrity | Tool descriptions, schemas, structural patterns, stored hashes | Tool poisoning, metadata changes / rug pulls, suspicious supply-chain content |
| 2: Parameter sanitization | Schema constraints, SQL/shell/prompt patterns, path traversal | Malicious outbound arguments |
| 3: Response analysis | Instructional spans, hidden content, context boundaries, session correlation | Indirect prompt injection and suspicious cross-tool chains |

Detection is heuristic or model-based, with false positives and false negatives. Stage 3 runs after a tool executes: it can withhold a response, but cannot undo a side effect. Parameter checks do not replace application authorization or a general execution sandbox.

## Proxy and configuration

```bash
shieldmcp init
shieldmcp scan examples/tools.json
shieldmcp proxy --server-id my-server -- python your_mcp_server.py
shieldmcp registry

# Legacy HTTP/SSE transport
shieldmcp sse-proxy --backend-url http://127.0.0.1:3000
```

The stdio proxy accepts newline-delimited JSON-RPC and Content-Length framing. Legacy SSE support is separate; Streamable HTTP is not implemented. See [default configuration](configs/default.yaml).

```yaml
stage1:
  semantic_backend: heuristic  # heuristic | llm_judge | classifier | tiered
  semantic_threshold: 0.72
  tiered_band_low: 0.12
stage3:
  instruction_detection_backend: heuristic  # heuristic | classifier | tiered
  tiered_min_words: 20
```

`classifier` uses local fine-tuned DistilBERT detectors. `tiered` routes selected ambiguous inputs through those classifiers after inexpensive heuristic checks. Download the trained artifacts or train locally using [model setup](models/README.md). The stage wrappers log a heuristic fallback if models/dependencies cannot load; confirm the models are loaded before treating a run as classifier evaluation. The `llm_judge` Stage 1 backend requires external model access.

## Python API

```python
import asyncio
from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.pipeline import ShieldPipeline

async def main():
    pipeline = ShieldPipeline(ShieldMCPConfig())
    await pipeline.initialize()
    try:
        action, tools, alerts = await pipeline.validate_tools("docs", [{
            "name": "read_page",
            "description": "Return the text of a document.",
            "inputSchema": {"type": "object", "properties": {
                "id": {"type": "string"}}, "required": ["id"]},
        }])
        action, alerts = await pipeline.process_tool_call(
            "docs", "read_page", {"id": "guide"}, session_id="review")
        action, content, alerts = await pipeline.process_tool_response(
            "docs", "read_page", "Document contents", session_id="review")
    finally:
        await pipeline.shutdown()

asyncio.run(main())
```

Integrators must honor returned actions before executing a call or giving content to an agent. The command-line proxy does this automatically.

## Experimental governance APIs

[PolicyEnforcedPipeline](src/shieldmcp/governance/enforcement.py) adds explicit failure policies, task-scoped tool exposure, and schema pinning. [SafetyGatedCache](src/shieldmcp/governance/response_cache.py) implements validated response caching with an eligibility predicate. These are opt-in Python APIs with synthetic benchmarks; they are **not wired into the default CLI proxy**. Integrators must provide the policy-aware wrapper and cache lifecycle themselves.

## Evaluation and development

```bash
pip install -e '.[all]'
pytest -q

# Framework detection evaluation: 487 attack + 200 benign scenarios
python eval/run_evaluation.py --framework-only --output-dir /tmp/shieldmcp-heuristic-review

# Requires trained artifacts; use separate output directories
python eval/run_evaluation.py --framework-only --backend classifier --output-dir /tmp/shieldmcp-classifier-review
python eval/run_evaluation.py --framework-only --backend tiered --output-dir /tmp/shieldmcp-tiered-review

python eval/benchmarks/latency_benchmark.py --iterations 1000
```

The framework harness measures detection on fixed synthetic scenarios. Its historical default result (8.6% attacks not detected; 95% benign pass) is not a live-agent exploit rate. Classifier validation and benchmark results are within-distribution; independent paraphrased, multilingual, encoded, long-context, and adaptive attacks remain important. [Raw evaluation outputs](eval/results/) and [training scripts](training/) are included for inspection.

[workshop/agent_console.py](workshop/agent_console.py) uses a local Ollama model with simulated page/email tools; blocked content is replaced with a known clean demo page. [examples/trust_issues_ui.py](examples/trust_issues_ui.py) animates a scripted conversation with a real Stage 3 verdict. Neither sends email. Use `examples/live_proxy_demo.py` for actual subprocess proxy traffic.

The [system demonstration paper](paper/EMNLP_Paper_Id_69_ShieldMCP_Demo_Track_AclPubCheck_Final.pdf) describes the research context. [HANDOFF.md](HANDOFF.md) records implementation status and verification boundaries.

## License

[Apache-2.0](LICENSE). The fine-tuned classifiers derive from the Apache-2.0 [DistilBERT base model](https://huggingface.co/distilbert/distilbert-base-uncased); see [model provenance](models/README.md).
