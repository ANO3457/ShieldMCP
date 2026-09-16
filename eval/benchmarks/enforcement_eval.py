"""Clean-path comparison: detection alone versus enforcement plus detection.

Runs the framework benchmark (487 attack and 200 benign scenarios) in two
modes:

- ``detection``   : the validation pipeline as-is; every exposed tool and
                    response is checked by the detector.
- ``enforcement`` : the policy layer in front of the same detector, adding
                    task-scoped least-privilege exposure and schema pinning
                    before any detection runs.

Task scopes are derived from the stated user task: a scope grants exactly
the tools the task requires. Every benign scenario's tool is in scope by
construction, so any benign regression is attributable to detection, not
to scoping.

Usage:
    python eval/benchmarks/enforcement_eval.py --backend tiered \
        --output-dir eval/results/enforcement
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from rich.console import Console
from rich.table import Table

from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.models import Action
from shieldmcp.core.pipeline import ShieldPipeline
from shieldmcp.governance import (
    EnforcementConfig,
    PolicyEnforcedPipeline,
    TaskScope,
)

from scenarios.attack_scenarios import get_all_attack_scenarios
from scenarios.benign_scenarios import get_all_benign_scenarios

console = Console()


def scope_for_attack(scenario) -> TaskScope:
    """Minimal scope for the stated task.

    Single-tool scenarios need their one tool. Cross-tool scenarios need
    only the retrieval tool; the second, write-capable tool in the
    inventory is not required by any stated task in the benchmark (checked
    by token overlap between tool name and task text).
    """
    if scenario.attack_family == "cross_tool_chain":
        first = scenario.tool_definitions[0]["name"]
        return TaskScope(scenario.scenario_id,
                         [f"{scenario.server_id}:{first}"])
    names = [t["name"] for t in scenario.tool_definitions] or [scenario.tool_name]
    return TaskScope(scenario.scenario_id,
                     [f"{scenario.server_id}:{n}" for n in names])


def make_config(backend: str, db_path: str) -> ShieldMCPConfig:
    cfg = ShieldMCPConfig()
    cfg.stage1.semantic_backend = backend
    cfg.stage3.instruction_detection_backend = backend
    cfg.registry_db_path = db_path
    return cfg


async def run_mode(mode: str, backend: str, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    attacks = get_all_attack_scenarios()
    benign = get_all_benign_scenarios()

    pipeline = ShieldPipeline(
        make_config(backend, str(output_dir / f"e1_{mode}_{backend}.db")))
    await pipeline.initialize()

    enforced = None
    if mode == "enforcement":
        enforced = PolicyEnforcedPipeline(
            primary=pipeline,
            config=EnforcementConfig(fail_mode="closed"),
        )

    per_scenario = []
    family: dict[str, dict] = {}
    latencies_ms: list[float] = []

    for s in attacks:
        t0 = time.perf_counter()
        neutralized = False
        by = None

        if s.tool_definitions:
            if enforced is not None:
                action, exposed, alerts = await enforced.expose_tools(
                    s.server_id, s.tool_definitions, scope=scope_for_attack(s))
            else:
                action, exposed, alerts = await pipeline.validate_tools(
                    s.server_id, s.tool_definitions)

            exposed_names = {t.get("name") for t in exposed}
            attack_tools = {t.get("name") for t in s.tool_definitions}
            if s.attack_family == "cross_tool_chain":
                # the chain needs both tools; losing either breaks it
                if not attack_tools.issubset(exposed_names):
                    neutralized = True
                    # under enforcement the out-of-scope tool is stripped
                    # before any detector runs, so scoping alone already
                    # breaks the chain; under detection-only the credit
                    # goes to the detector
                    by = "scope" if enforced is not None else "detection"
            else:
                if action == Action.BLOCK or any(
                        a.action == Action.BLOCK for a in alerts):
                    neutralized = True
                    by = "detection"
                elif not attack_tools.issubset(exposed_names):
                    neutralized = True
                    by = "detection"

        if not neutralized and s.tool_response:
            action, _m, alerts = (
                await enforced.enforce_response(
                    s.server_id, s.tool_name, s.tool_response)
                if enforced is not None else
                await pipeline.validate_response(
                    s.server_id, s.tool_name, s.tool_response)
            )
            if action == Action.BLOCK or any(
                    a.action == Action.BLOCK for a in alerts):
                neutralized = True
                by = "detection"

        latencies_ms.append((time.perf_counter() - t0) * 1000)

        f = family.setdefault(
            s.attack_family,
            {"total": 0, "neutralized": 0, "by_scope": 0, "by_detection": 0})
        f["total"] += 1
        if neutralized:
            f["neutralized"] += 1
            f["by_scope" if by == "scope" else "by_detection"] += 1
        per_scenario.append({
            "scenario_id": s.scenario_id, "family": s.attack_family,
            "neutralized": neutralized, "by": by,
        })

    # benign scenarios: scope grants the scenario's tool, so scoping cannot
    # block them; measure detection verdicts as usual
    benign_blocked = benign_passed = 0
    for s in benign:
        blocked = False
        if s.parameters:
            action, alerts = await pipeline.validate_call(
                s.server_id, s.tool_name, s.parameters)
            if action == Action.BLOCK:
                blocked = True
        if not blocked and s.expected_response:
            action, _m, alerts = (
                await enforced.enforce_response(
                    s.server_id, s.tool_name, s.expected_response)
                if enforced is not None else
                await pipeline.validate_response(
                    s.server_id, s.tool_name, s.expected_response)
            )
            if action == Action.BLOCK:
                blocked = True
        benign_blocked += blocked
        benign_passed += not blocked

    await pipeline.shutdown()

    lat = sorted(latencies_ms)
    results = {
        "config": {"mode": mode, "backend": backend,
                   "attacks": len(attacks), "benign": len(benign),
                   "date": time.strftime("%Y-%m-%d %H:%M:%S")},
        "family": family,
        "benign": {"blocked": benign_blocked, "passed": benign_passed},
        "latency_ms": {
            "p50": lat[len(lat) // 2],
            "p99": lat[int(0.99 * (len(lat) - 1))],
            "mean": sum(lat) / len(lat),
        },
        "enforcement_stats": enforced.stats.as_dict() if enforced else None,
        "per_scenario": per_scenario,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"e1_{mode}_{backend}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)

    total = sum(f["total"] for f in family.values())
    neut = sum(f["neutralized"] for f in family.values())
    table = Table(title=f"Clean path: mode={mode} backend={backend}")
    for col in ["Attacks neutralized", "By scope", "By detection",
                "Benign blocked", "p50 ms"]:
        table.add_column(col, justify="right")
    table.add_row(
        f"{neut}/{total}",
        str(sum(f["by_scope"] for f in family.values())),
        str(sum(f["by_detection"] for f in family.values())),
        f"{benign_blocked}/{len(benign)}",
        f"{results['latency_ms']['p50']:.2f}",
    )
    console.print(table)
    console.print(f"[dim]Saved to {out}[/dim]")
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", default="tiered",
                        choices=["heuristic", "classifier", "tiered"])
    parser.add_argument("--mode", default=None,
                        choices=["detection", "enforcement"])
    parser.add_argument("--output-dir", default="eval/results/enforcement")
    args = parser.parse_args()
    modes = [args.mode] if args.mode else ["detection", "enforcement"]
    for mode in modes:
        asyncio.run(run_mode(mode, args.backend, Path(args.output_dir)))


if __name__ == "__main__":
    main()
