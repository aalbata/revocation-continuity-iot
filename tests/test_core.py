"""Deterministic tests of the decision rules in core.DomainCore."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rcbench.core import DomainCore, DurableStore, Io, Store  # noqa: E402
from rcbench.policy import get  # noqa: E402
from rcbench.statuslist import Bitstring, list_credential, status_entry  # noqa: E402

ISSUER = "did:web:issuer-a.rcbench.test"
OTHER = "did:web:issuer-b.rcbench.test"
REV = "https://issuer-a.rcbench.test/status/revocation"
SUS = "https://issuer-a.rcbench.test/status/suspension"
OTHER_REV = "https://issuer-b.rcbench.test/status/revocation"
TRUST = {ISSUER: {"lists": {"revocation": REV, "suspension": SUS}, "organizations": ["contractor"]},
         OTHER: {"lists": {"revocation": OTHER_REV}, "organizations": ["operator"]}}
HOLDER = "did:key:z6MkTestHolder"
BUDGET = 30.0


def lists(at: float, sequence: int = 1, revoked=(), suspended=(), epoch="e1", issuer=ISSUER):
    out = []
    for purpose, list_id, flags in (("revocation", REV, revoked), ("suspension", SUS, suspended)):
        bits = Bitstring()
        for index in flags:
            bits.set(index, True)
        coverage = {"authority": issuer, "epoch": epoch, "sequence": sequence, "covered_through": at}
        out.append(list_credential(list_id, issuer, purpose, bits, at, at + 300.0, 5000, coverage))
    return out


class FakeIo(Io):
    def __init__(self):
        self.available = None
        self.provisioned = set()
        self.count = 0
        self.valid_proofs = True

    def fetch_lists(self, issuer):
        return self.available

    def verify_list(self, credential):
        return self.valid_proofs

    def provision(self, session):
        self.provisioned.add(session["username"])

    def unprovision(self, session):
        self.provisioned.discard(session["username"])

    def sign_token(self, claims):
        return claims

    def new_id(self):
        self.count += 1
        return f"id{self.count}"


def make(policy_key: str, store=None, **overrides):
    io = FakeIo()
    events = []
    core = DomainCore("building", get(policy_key, **overrides), BUDGET, TRUST, store or Store(), io,
                      lambda ev, **fields: events.append((ev, fields)))
    return core, io, events


def credential(index: int = 7, holder: str = HOLDER, issuer: str = ISSUER, organization: str = "contractor"):
    return {"id": "urn:uuid:test-" + str(index), "issuer": issuer, "validUntil": None,
            "credentialSubject": {"id": holder, "deviceId": "d001", "organization": organization,
                                  "allowedAction": ["command"]},
            "credentialStatus": [status_entry(REV, "revocation", index), status_entry(SUS, "suspension", index)]}


OK = {"verified": True, "category": "OK"}


def test_deadline_is_inherited_from_evidence():
    core, io, _ = make("profile")
    grant = core.present(OK, credential(), HOLDER, lists(100.0), 110.0)
    assert grant["granted"] and abs(grant["deadline"] - 130.0) < 1e-6
    core2, _, _ = make("no_inherit")
    grant2 = core2.present(OK, credential(), HOLDER, lists(100.0), 110.0)
    assert grant2["granted"] and abs(grant2["deadline"] - 170.0) < 1e-6


def test_handover_does_not_extend_parent_deadline_without_fresher_evidence():
    source, _, _ = make("profile")
    parent = source.present(OK, credential(), HOLDER, lists(100.0), 105.0)["token"]
    target, _, _ = make("profile")
    child = target.handover(parent, lists(100.0), 120.0)
    assert child["granted"] and child["deadline"] <= parent["dl"]
    assert child["token"]["par"] == parent["jti"] and child["token"]["src"] == parent["src"]
    fresher = target.handover(parent, lists(119.0, sequence=2), 120.0)
    assert fresher["granted"] and fresher["deadline"] > parent["dl"]


def test_older_evidence_is_rejected_by_the_profile_and_restarts_the_timer_in_the_negative_control():
    core, _, _ = make("profile")
    assert core.ingest(lists(100.0, sequence=2, revoked=[7])[0], "push", 101.0) == "accepted"
    assert core.ingest(lists(90.0, sequence=1)[0], "stapled", 102.0) == "rejected_older"
    assert core.present(OK, credential(), HOLDER, lists(90.0, sequence=1), 103.0)["reason"] in ("revoked", "evidence_unknown")
    control, _, _ = make("timer_reset")
    assert control.ingest(lists(100.0, sequence=2, revoked=[7])[0], "fetch", 101.0) == "accepted"
    grant = control.present(OK, credential(), HOLDER, lists(90.0, sequence=1), 125.0)
    assert grant["granted"] and abs(grant["deadline"] - 185.0) < 1e-6
    assert control.store.evidence[REV].received_at == 125.0 and control.store.evidence[REV].sequence == 1


def test_epoch_and_authority_are_bound():
    core, _, _ = make("profile")
    assert core.ingest(lists(100.0)[0], "fetch", 100.0) == "accepted"
    assert core.ingest(lists(101.0, epoch="e2")[0], "fetch", 101.0) == "rejected_epoch"
    forged = lists(101.0, issuer=OTHER)[0]
    assert core.ingest(forged, "fetch", 101.0) == "rejected_authority"
    foreign = credential()
    foreign["credentialStatus"] = [status_entry(OTHER_REV, "revocation", 7)]
    assert core.present(OK, foreign, HOLDER, [], 101.0)["reason"] == "status_authority"


def test_unknown_and_stale_evidence_deny():
    core, io, _ = make("profile")
    assert core.present(OK, credential(), HOLDER, [], 100.0)["reason"] == "evidence_unknown"
    assert core.present(OK, credential(), HOLDER, lists(60.0), 100.0)["reason"] == "evidence_stale"
    io.available = lists(99.0, sequence=2)
    assert core.present(OK, credential(), HOLDER, lists(60.0), 100.0)["granted"]


def test_revocation_ends_live_sessions_and_blocks_operations():
    core, io, _ = make("profile")
    grant = core.present(OK, credential(), HOLDER, lists(100.0), 100.0)
    token, topic = grant["token"], grant["topic"]
    assert grant["username"] in io.provisioned
    assert core.authorize_operation(token, topic, 101.0) == "ok"
    core.on_push(lists(102.0, sequence=2, revoked=[7]), 102.0)
    assert grant["username"] not in io.provisioned
    assert core.authorize_operation(token, topic, 102.5) == "no_session"
    assert core.present(OK, credential(), HOLDER, [], 103.0)["reason"] == "revoked"


def test_token_only_check_allows_until_expiry_and_scope_is_enforced():
    core, io, _ = make("cached")
    io.available = lists(100.0)
    grant = core.present(OK, credential(), HOLDER, [], 100.0)
    token = grant["token"]
    io.available = lists(105.0, sequence=2, revoked=[7])
    core.refresh(lambda: 105.0)
    assert core.authorize_operation(token, grant["topic"], 129.0) == "ok"
    assert core.authorize_operation(token, grant["topic"], 131.0) == "token_expired"
    assert core.authorize_operation(token, "rc/building/cmd/d999", 110.0) == "scope"
    assert core.authorize_operation(None, grant["topic"], 110.0) == "token_invalid"


def test_cached_policy_ignores_stapled_lists():
    core, io, _ = make("cached")
    assert core.present(OK, credential(), HOLDER, lists(100.0), 100.0)["reason"] == "evidence_unknown"


def test_online_policy_fails_closed():
    core, io, _ = make("online")
    assert core.present(OK, credential(), HOLDER, [], 100.0)["reason"] == "status_unreachable"
    io.available = lists(100.0)
    grant = core.present(OK, credential(), HOLDER, [], 100.0)
    assert grant["granted"]
    io.available = None
    assert core.authorize_operation(grant["token"], grant["topic"], 101.0) == "status_unreachable"
    io.available, io.valid_proofs = lists(101.0), False
    assert core.authorize_operation(grant["token"], grant["topic"], 101.0) == "status_unverified"
    io.available, io.valid_proofs = lists(102.0, sequence=2, revoked=[7]), True
    assert core.authorize_operation(grant["token"], grant["topic"], 102.0) == "revoked"


def test_suspension_is_reversible():
    core, _, _ = make("profile")
    assert core.present(OK, credential(), HOLDER, lists(100.0, sequence=2, suspended=[7]), 100.0)["reason"] == "suspended"
    assert core.present(OK, credential(), HOLDER, lists(110.0, sequence=3), 110.0)["granted"]


def test_reused_index_of_a_revoked_credential_is_denied():
    core, _, _ = make("profile")
    reissued = credential()
    reissued["id"] = "urn:uuid:reissued"
    assert core.present(OK, reissued, HOLDER, lists(100.0, sequence=2, revoked=[7]), 100.0)["reason"] == "revoked"


def test_presentation_checks():
    core, _, _ = make("profile")
    assert core.present({"verified": False, "category": "PROOF"}, credential(), HOLDER, lists(100.0), 100.0)["reason"] == "credential_proof"
    assert core.present(OK, credential(holder="did:key:other"), HOLDER, lists(100.0), 100.0)["reason"] == "holder_mismatch"
    assert core.present(OK, credential(organization="operator"), HOLDER, lists(100.0), 100.0)["reason"] == "untrusted_issuer"


def test_persistent_state_survives_restart(tmp_path):
    path = str(tmp_path / "state" / "building.sqlite")
    core, io, _ = make("profile", DurableStore(path))
    grant = core.present(OK, credential(index=9), HOLDER, lists(100.0), 100.0)
    core.on_push(lists(101.0, sequence=2, revoked=[7]), 101.0)
    restored, io2, _ = make("profile", DurableStore(path))
    restored.restart([grant["username"], "s-unknown"], 102.0)
    assert grant["token"]["sid"] in restored.store.sessions
    assert restored.present(OK, credential(), HOLDER, lists(100.0), 103.0)["reason"] == "revoked"
    volatile, _, _ = make("no_persist")
    assert volatile.present(OK, credential(), HOLDER, lists(100.0), 103.0)["granted"]


def test_session_deadline_and_reauthorization():
    core, io, _ = make("profile")
    grant = core.present(OK, credential(), HOLDER, lists(100.0), 100.0)
    core.tick(129.0)
    assert grant["username"] in io.provisioned
    core.tick(130.5)
    assert grant["username"] not in io.provisioned
    loose, io2, _ = make("no_session")
    grant2 = loose.present(OK, credential(), HOLDER, lists(100.0), 100.0)
    loose.on_push(lists(101.0, sequence=2, revoked=[7]), 101.0)
    loose.tick(500.0)
    assert grant2["username"] in io2.provisioned
    assert loose.authorize_operation(grant2["token"], grant2["topic"], 500.0) == "ok"


def test_renewal_requires_fresher_evidence_to_extend():
    core, io, _ = make("profile")
    grant = core.present(OK, credential(), HOLDER, lists(100.0), 100.0)
    same = core.renew(grant["token"], lists(100.0), 120.0)
    assert same["granted"] and abs(same["deadline"] - grant["deadline"]) < 1e-6
    later = core.renew(same["token"], lists(125.0, sequence=1), 126.0)
    assert later["granted"] and later["deadline"] > grant["deadline"]
    core.on_push(lists(127.0, sequence=2, revoked=[7]), 127.0)
    assert core.renew(later["token"], [], 128.0)["reason"] == "unknown_session"
