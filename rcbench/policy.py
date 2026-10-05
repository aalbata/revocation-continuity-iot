"""Integration policies compared by the benchmark.

A policy is a set of switches over one common gateway and executor
implementation (core.DomainCore). The freshness budget is a world setting shared
by every policy so that comparisons use matched budgets. The token lifetimes of
the two caching baselines (30 s and 5 s) were chosen on the pilot seeds at outages
of 0 and 30 s. Among the candidates 30, 60, and 120 s, and 5, 10, and 20 s, each
is the one with the lowest exposure whose benign completion stayed within one
percentage point of the best candidate. The middle candidate of each family was
run on ten pilot seeds and the other candidates on three.
"""
from dataclasses import asdict, dataclass

POLICY_VERSION = "2026-10"


@dataclass(frozen=True)
class Policy:
    key: str
    label: str
    role: str
    status_mode: str            # online | cache | origin
    token_lifetime: float       # seconds granted to a token before other limits apply
    inherit_deadline: bool      # child deadline never exceeds parent, evidence, and credential limits
    accept_stapled: bool        # holder may supply a signed status list
    monotonic_evidence: bool    # reject evidence older than the newest already accepted
    use_coverage: bool          # evidence age and ordering come from the signed coverage statement
    push: bool                  # issuer notifications are applied
    enforce_session_expiry: bool
    revoke_live_sessions: bool  # revocation knowledge is applied to established sessions
    reauth_interval: float      # seconds between session rechecks, 0 disables
    per_op: str                 # none | token | full | online
    persistent: bool            # evidence, high-water marks, and sessions survive a restart
    restart_sessions: str       # drop | restore | orphan
    session_lifetime: float = 0.0   # 0 means the session follows the token deadline

    def to_dict(self) -> dict:
        return asdict(self)


def refresh_interval(budget: float) -> float:
    """Status list refresh period used by every caching policy."""
    return min(5.0, budget / 5.0)


_BASE = dict(token_lifetime=60.0, inherit_deadline=False, accept_stapled=False, monotonic_evidence=False,
             use_coverage=False, push=False, enforce_session_expiry=True, revoke_live_sessions=False,
             reauth_interval=0.0, per_op="token", persistent=False, restart_sessions="drop")
_PROFILE = dict(_BASE, status_mode="origin", inherit_deadline=True, accept_stapled=True,
                monotonic_evidence=True, use_coverage=True, push=True, revoke_live_sessions=True,
                reauth_interval=5.0, per_op="full", persistent=True, restart_sessions="restore")

POLICIES = {p.key: p for p in [
    Policy("online", "Online checks", "baseline", **dict(_BASE, status_mode="online", per_op="online")),
    Policy("cached", "Cached status", "baseline", **dict(_BASE, status_mode="cache", token_lifetime=30.0)),
    Policy("shortlived", "Short-lived grants", "baseline", **dict(_BASE, status_mode="cache", token_lifetime=5.0)),
    Policy("coordinated", "Coordinated practice", "baseline",
           **dict(_PROFILE, use_coverage=False, per_op="token", persistent=False, restart_sessions="drop")),
    Policy("profile", "Continuity profile", "profile", **_PROFILE),
    Policy("no_inherit", "Profile without inheritance", "ablation", **dict(_PROFILE, inherit_deadline=False)),
    Policy("no_persist", "Profile without persistence", "ablation",
           **dict(_PROFILE, persistent=False, restart_sessions="drop")),
    Policy("no_session", "Profile without session enforcement", "ablation",
           **dict(_PROFILE, enforce_session_expiry=False, revoke_live_sessions=False, reauth_interval=0.0,
                  per_op="none")),
    Policy("timer_reset", "Timer-reset control", "negative control",
           **dict(_BASE, status_mode="cache", accept_stapled=True, restart_sessions="orphan")),
]}

MAIN = ["online", "cached", "shortlived", "coordinated", "profile"]
ALL = list(POLICIES)


def get(key: str, **overrides) -> Policy:
    """Return a policy, optionally with fields replaced for sensitivity sweeps."""
    base = POLICIES[key]
    return Policy(**dict(base.to_dict(), **overrides)) if overrides else base
