"""Policy-aware enforcement layer for the validation pipeline.

Detection decides whether a single artifact looks malicious. Enforcement
decides what the proxy does when detection cannot run, when the tool
inventory drifts after approval, or when a task never needed a tool in the
first place. Three mechanisms live here:

- an explicit failure policy (fail-open, fail-closed, or tiered degradation
  to a simpler detector) applied whenever a validation component raises,
  with every decision recorded as an auditable event;
- task-scoped least-privilege exposure: tools outside the declared task
  scope are stripped from the inventory before the agent ever sees them;
- schema pinning: the content hash of every approved tool is pinned, and a
  call to a tool whose definition has drifted since approval is held until
  the new definition re-validates clean.
"""

from __future__ import annotations

import fnmatch
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable

from ..core.models import Action, SecurityAlert, ToolSignature

logger = logging.getLogger("shieldmcp.enforcement")


class FailMode(str, Enum):
    """What the proxy does when a validation component is unavailable."""

    OPEN = "open"          # serve unvalidated traffic (availability first)
    CLOSED = "closed"      # refuse service (security first)
    TIERED = "tiered"      # degrade to the fallback detector, refuse only
                           # if the fallback is unavailable too


class ComponentUnavailable(RuntimeError):
    """Raised when a validation component cannot produce a verdict."""

    def __init__(self, component: str, cause: str = "") -> None:
        super().__init__(f"validation component unavailable: {component} {cause}")
        self.component = component


@dataclass
class EnforcementConfig:
    fail_mode: str = FailMode.TIERED.value
    scope_enforcement: bool = True
    schema_pinning: bool = True
    alert_on_degraded: bool = True


@dataclass
class EnforcementEvent:
    """One auditable enforcement decision."""

    kind: str          # "degraded", "refused", "served_unvalidated",
                       # "scope_stripped", "schema_drift_block",
                       # "schema_repinned"
    detail: str
    server_id: str | None = None
    tool_name: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
        }


@dataclass
class EnforcementStats:
    primary_failures: int = 0
    fallback_failures: int = 0
    degraded_verdicts: int = 0
    refusals: int = 0
    served_unvalidated: int = 0
    scope_stripped: int = 0
    drift_blocks: int = 0
    repins: int = 0

    def as_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


class TaskScope:
    """Least-privilege exposure policy for one task or session.

    ``allowed`` holds ``server_id:tool_name`` patterns; fnmatch wildcards are
    supported so an operator can write ``files:read_*`` or ``search:*``.
    """

    def __init__(self, scope_id: str, allowed: list[str]) -> None:
        self.scope_id = scope_id
        self.allowed = list(allowed)

    def permits(self, server_id: str, tool_name: str) -> bool:
        target = f"{server_id}:{tool_name}"
        return any(fnmatch.fnmatch(target, pat) for pat in self.allowed)


class SchemaPinStore:
    """Content hashes of approved tool definitions, keyed per server:tool."""

    def __init__(self) -> None:
        self._pins: dict[str, str] = {}

    def pin(self, server_id: str, tool_name: str, content_hash: str) -> None:
        self._pins[f"{server_id}:{tool_name}"] = content_hash

    def check(self, server_id: str, tool_name: str, content_hash: str) -> str:
        """Return "unpinned", "match", or "drift"."""
        pinned = self._pins.get(f"{server_id}:{tool_name}")
        if pinned is None:
            return "unpinned"
        return "match" if pinned == content_hash else "drift"


# A validation callable returns (action, payload, alerts); the enforcement
# layer treats primary and fallback uniformly through this signature.
Validator = Callable[..., Awaitable[tuple[Action, Any, list[SecurityAlert]]]]


class PolicyEnforcedPipeline:
    """Wraps a primary and a fallback validation pipeline with an explicit
    failure policy, scoped exposure, and schema pinning.

    ``primary`` and ``fallback`` are ShieldPipeline instances (or anything
    with the same validate_tools / validate_call / validate_response
    surface). The fallback is expected to be a cheaper, more available
    detector such as the pattern-heuristic backend.
    """

    def __init__(
        self,
        primary: Any,
        fallback: Any | None = None,
        config: EnforcementConfig | None = None,
    ) -> None:
        self.primary = primary
        self.fallback = fallback
        self.config = config or EnforcementConfig()
        self.pins = SchemaPinStore()
        self.stats = EnforcementStats()
        self.events: list[EnforcementEvent] = []

    # --- internals -------------------------------------------------------

    def _record(self, kind: str, detail: str, server_id: str | None = None,
                tool_name: str | None = None) -> None:
        event = EnforcementEvent(kind=kind, detail=detail,
                                 server_id=server_id, tool_name=tool_name)
        self.events.append(event)
        if self.config.alert_on_degraded:
            logger.warning("[enforcement] %s: %s (%s:%s)",
                           kind, detail, server_id, tool_name)

    async def _apply_policy(
        self,
        op_name: str,
        primary_call: Callable[[], Awaitable[tuple]],
        fallback_call: Callable[[], Awaitable[tuple]] | None,
        pass_result: tuple,
        block_result: tuple,
        server_id: str | None,
        tool_name: str | None,
    ) -> tuple:
        """Run a validation op under the configured failure policy."""
        try:
            return await primary_call()
        except Exception as exc:
            self.stats.primary_failures += 1
            mode = FailMode(self.config.fail_mode)

            if mode == FailMode.OPEN:
                self.stats.served_unvalidated += 1
                self._record("served_unvalidated",
                             f"{op_name} primary unavailable ({exc}); "
                             "policy is fail-open", server_id, tool_name)
                return pass_result

            if mode == FailMode.CLOSED:
                self.stats.refusals += 1
                self._record("refused",
                             f"{op_name} primary unavailable ({exc}); "
                             "policy is fail-closed", server_id, tool_name)
                return block_result

            # tiered: degrade to the fallback detector
            if fallback_call is not None:
                try:
                    result = await fallback_call()
                    self.stats.degraded_verdicts += 1
                    self._record("degraded",
                                 f"{op_name} degraded to fallback detector "
                                 f"({exc})", server_id, tool_name)
                    return result
                except Exception as exc2:
                    self.stats.fallback_failures += 1
                    self.stats.refusals += 1
                    self._record("refused",
                                 f"{op_name} fallback also unavailable "
                                 f"({exc2}); refusing", server_id, tool_name)
                    return block_result
            self.stats.refusals += 1
            self._record("refused",
                         f"{op_name} no fallback configured; refusing",
                         server_id, tool_name)
            return block_result

    @staticmethod
    def _signature(server_id: str, tool: dict[str, Any]) -> ToolSignature:
        return ToolSignature(
            server_id=server_id,
            name=tool.get("name", ""),
            description=tool.get("description", ""),
            parameters=tool.get("inputSchema", tool.get("parameters", {})),
            return_type=tool.get("returnType"),
        )

    # --- inventory exposure (tools/list boundary) ------------------------

    async def expose_tools(
        self,
        server_id: str,
        tools: list[dict[str, Any]],
        scope: TaskScope | None = None,
    ) -> tuple[Action, list[dict[str, Any]], list[SecurityAlert]]:
        """Scope-filter, validate, and pin a tool inventory.

        Tools outside the task scope are stripped before validation and are
        never exposed to the agent. Tools that validate clean have their
        content hash pinned for call-time drift checks.
        """
        in_scope = tools
        if self.config.scope_enforcement and scope is not None:
            in_scope = []
            for t in tools:
                if scope.permits(server_id, t.get("name", "")):
                    in_scope.append(t)
                else:
                    self.stats.scope_stripped += 1
                    self._record("scope_stripped",
                                 f"outside scope {scope.scope_id}",
                                 server_id, t.get("name"))

        if not in_scope:
            return Action.PASS, [], []

        action, filtered, alerts = await self._apply_policy(
            "validate_tools",
            lambda: self.primary.validate_tools(server_id, in_scope),
            (lambda: self.fallback.validate_tools(server_id, in_scope))
            if self.fallback is not None else None,
            pass_result=(Action.PASS, in_scope, []),
            block_result=(Action.BLOCK, [], []),
            server_id=server_id, tool_name=None,
        )

        if self.config.schema_pinning:
            approved = {t.get("name") for t in filtered}
            for t in in_scope:
                if t.get("name") in approved:
                    sig = self._signature(server_id, t)
                    self.pins.pin(server_id, sig.name, sig.content_hash)
        return action, filtered, alerts

    # --- call boundary ---------------------------------------------------

    async def enforce_call(
        self,
        server_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        current_definition: dict[str, Any] | None = None,
        scope: TaskScope | None = None,
        session_id: str | None = None,
    ) -> tuple[Action, list[SecurityAlert]]:
        """Enforce scope, schema pin, and parameter validation on one call.

        ``current_definition`` is the tool definition as the server reports
        it at call time; passing it enables drift detection between
        inventory refreshes.
        """
        if self.config.scope_enforcement and scope is not None:
            if not scope.permits(server_id, tool_name):
                self.stats.scope_stripped += 1
                self._record("scope_stripped",
                             f"call outside scope {scope.scope_id}",
                             server_id, tool_name)
                return Action.BLOCK, []

        if self.config.schema_pinning and current_definition is not None:
            sig = self._signature(server_id, current_definition)
            status = self.pins.check(server_id, tool_name, sig.content_hash)
            if status != "match":
                # drifted since approval, or never approved at all; either
                # way the current definition must validate clean before any
                # call is allowed
                if status == "drift":
                    self.stats.drift_blocks += 1
                    self._record("schema_drift_block",
                                 "definition changed since approval; "
                                 "re-validating before any call is allowed",
                                 server_id, tool_name)
                action, revalidated, _alerts = await self.expose_tools(
                    server_id, [current_definition], scope=scope,
                )
                if revalidated and action != Action.BLOCK:
                    if status == "drift":
                        self.stats.repins += 1
                        self._record("schema_repinned",
                                     "drifted definition re-validated clean",
                                     server_id, tool_name)
                else:
                    if status == "unpinned":
                        self._record("refused",
                                     "unapproved tool failed validation at "
                                     "first call", server_id, tool_name)
                    return Action.BLOCK, []

        action, alerts = await self._apply_policy(
            "validate_call",
            lambda: self.primary.validate_call(
                server_id, tool_name, parameters, session_id),
            (lambda: self.fallback.validate_call(
                server_id, tool_name, parameters, session_id))
            if self.fallback is not None else None,
            pass_result=(Action.PASS, []),
            block_result=(Action.BLOCK, []),
            server_id=server_id, tool_name=tool_name,
        )
        return action, alerts

    # --- response boundary -----------------------------------------------

    async def enforce_response(
        self,
        server_id: str,
        tool_name: str,
        content: Any,
        session_id: str | None = None,
    ) -> tuple[Action, Any, list[SecurityAlert]]:
        return await self._apply_policy(
            "validate_response",
            lambda: self.primary.validate_response(
                server_id, tool_name, content, session_id=session_id),
            (lambda: self.fallback.validate_response(
                server_id, tool_name, content, session_id=session_id))
            if self.fallback is not None else None,
            pass_result=(Action.PASS, content, []),
            block_result=(Action.BLOCK, None, []),
            server_id=server_id, tool_name=tool_name,
        )
