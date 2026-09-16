"""Replay workload with injected component failures.

Replays a Zipf-distributed stream of tool responses through the enforcement
layer while the primary detector fails with a configurable probability, and
measures how each failure policy trades security against availability:

- ``open``   : unavailable detector means the response is served raw.
- ``closed`` : unavailable detector means the request is refused.
- ``tiered`` : unavailable detector means the verdict comes from the
               pattern-heuristic fallback; the request is refused only if
               the fallback is unavailable in the same instant.

Failure draws are precomputed per request index from a seed-derived stream,
so for a given seed every policy sees the identical workload and the
identical outage pattern. An unsafe serve is a poisoned response delivered
without a blocking verdict on that delivery.

Usage:
    python eval/benchmarks/failure_injection.py --requests 2000 --seed 7 \
        --fail-rate 0.05 --policy tiered --output-dir eval/results/failures
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
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
    ComponentUnavailable,
    EnforcementConfig,
    PolicyEnforcedPipeline,
)

from benchmarks.cache_workload import build_population, zipf_ranks

console = Console()


class FlakyPipeline:
    """Wraps a pipeline; raises ComponentUnavailable on scheduled requests."""

    def __init__(self, inner: ShieldPipeline, name: str) -> None:
        self.inner = inner
        self.name = name
        self.fail_now = False

    async def validate_response(self, server_id, tool_name, content,
                                session_id=None):
        if self.fail_now:
            raise ComponentUnavailable(self.name)
        return await self.inner.validate_response(
            server_id, tool_name, content, session_id=session_id)


async def run_workload(
    requests: int,
    seed: int,
    policy: str,
    fail_rate: float,
    zipf_s: float,
    output_dir: Path,
    primary_backend: str = "classifier",
) -> dict:
    rng = random.Random(seed)
    population = build_population()
    rng.shuffle(population)
    ranks = zipf_ranks(len(population), requests, zipf_s, rng)

    # identical outage pattern across policies for a given seed
    rng_fail = random.Random(seed + 1000)
    primary_down = [rng_fail.random() < fail_rate for _ in range(requests)]
    rng_fb = random.Random(seed + 2000)
    fallback_down = [rng_fb.random() < fail_rate for _ in range(requests)]

    output_dir.mkdir(parents=True, exist_ok=True)

    def make_pipeline(backend: str, tag: str) -> ShieldPipeline:
        cfg = ShieldMCPConfig()
        cfg.stage1.semantic_backend = backend
        cfg.stage3.instruction_detection_backend = backend
        cfg.registry_db_path = str(
            output_dir / f"fi_{policy}_{tag}_{seed}.db")
        return ShieldPipeline(cfg)

    primary_inner = make_pipeline(primary_backend, "p")
    await primary_inner.initialize()
    primary = FlakyPipeline(primary_inner, primary_backend)

    fallback_inner = None
    fallback = None
    if policy == "tiered":
        fallback_inner = make_pipeline("heuristic", "f")
        await fallback_inner.initialize()
        fallback = FlakyPipeline(fallback_inner, "heuristic")

    enforced = PolicyEnforcedPipeline(
        primary=primary,
        fallback=fallback,
        config=EnforcementConfig(fail_mode=policy),
    )

    poisoned_requests = benign_requests = 0
    unsafe_serves = benign_served = benign_refused = benign_false_blocked = 0
    poisoned_refused = poisoned_detector_blocked = 0
    latencies_ms: list[float] = []

    t_start = time.perf_counter()
    for i in range(requests):
        item = population[ranks[i]]
        primary.fail_now = primary_down[i]
        if fallback is not None:
            fallback.fail_now = fallback_down[i]

        refusals_before = enforced.stats.refusals
        t0 = time.perf_counter()
        action, _content, alerts = await enforced.enforce_response(
            item["server_id"], item["tool_name"], item["response"])
        latencies_ms.append((time.perf_counter() - t0) * 1000)

        blocked = action == Action.BLOCK or any(
            a.action.value in ("block", "quarantine") for a in alerts)
        refused = enforced.stats.refusals > refusals_before

        if item["poisoned"]:
            poisoned_requests += 1
            if not blocked:
                unsafe_serves += 1
            elif refused:
                poisoned_refused += 1
            else:
                poisoned_detector_blocked += 1
        else:
            benign_requests += 1
            if not blocked:
                benign_served += 1
            elif refused:
                benign_refused += 1
            else:
                benign_false_blocked += 1

    wall_s = time.perf_counter() - t_start
    await primary_inner.shutdown()
    if fallback_inner is not None:
        await fallback_inner.shutdown()

    lat = sorted(latencies_ms)

    def pct(p: float) -> float:
        return lat[int(round((p / 100) * (len(lat) - 1)))]

    results = {
        "config": {
            "requests": requests, "seed": seed, "policy": policy,
            "fail_rate": fail_rate, "zipf_s": zipf_s,
            "primary_backend": primary_backend,
            "population": len(population),
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "outcomes": {
            "poisoned_requests": poisoned_requests,
            "benign_requests": benign_requests,
            "unsafe_serves": unsafe_serves,
            "poisoned_refused": poisoned_refused,
            "poisoned_detector_blocked": poisoned_detector_blocked,
            "benign_served": benign_served,
            "benign_refused": benign_refused,
            "benign_false_blocked": benign_false_blocked,
            "enforcement_stats": enforced.stats.as_dict(),
        },
        "latency_ms": {
            "p50": pct(50), "p95": pct(95), "p99": pct(99),
            "mean": sum(lat) / len(lat), "wall_seconds": wall_s,
        },
    }

    out = output_dir / f"fi_{policy}_r{fail_rate}_s{seed}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)

    table = Table(title=f"Failure injection: policy={policy} "
                        f"rate={fail_rate} seed={seed}")
    for col in ["Unsafe serves", "Poisoned reqs", "Benign served",
                "Benign refused", "Benign blocked", "Degraded", "p50 ms"]:
        table.add_column(col, justify="right")
    table.add_row(
        str(unsafe_serves), str(poisoned_requests), str(benign_served),
        str(benign_refused), str(benign_false_blocked),
        str(enforced.stats.degraded_verdicts), f"{pct(50):.2f}",
    )
    console.print(table)
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--zipf-s", type=float, default=1.1)
    parser.add_argument("--fail-rate", type=float, default=0.05)
    parser.add_argument("--policy", default="tiered",
                        choices=["open", "closed", "tiered"])
    parser.add_argument("--primary-backend", default="classifier")
    parser.add_argument("--output-dir", default="eval/results/failures")
    args = parser.parse_args()
    asyncio.run(run_workload(
        args.requests, args.seed, args.policy, args.fail_rate,
        args.zipf_s, Path(args.output_dir),
        primary_backend=args.primary_backend,
    ))


if __name__ == "__main__":
    main()
