"""Deterministic tests of proofs, status lists, tokens, traces, and the simulator."""
import base64
import gzip
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rcbench import di, tokens, vc  # noqa: E402
from rcbench.sim import simulate  # noqa: E402
from rcbench.statuslist import MIN_ENTRIES, Bitstring, Evidence, StatusError, list_credential, status_entry  # noqa: E402
from rcbench.trace import scenario  # noqa: E402

NOW = 1790000000.0
ISSUER = "did:web:issuer-a.rcbench.test"
LIST = "https://issuer-a.rcbench.test/status/revocation"


def issuer_key():
    return di.KeyPair(ISSUER, "key-1", hashlib.sha256(b"test-issuer").digest())


def documents(key):
    return {ISSUER: {"@context": [di.DID_CONTEXT, di.MULTIKEY_CONTEXT], "id": ISSUER,
                     "verificationMethod": [key.method()], "assertionMethod": [key.id], "authentication": [key.id]}}


def test_base58_and_multikey_round_trip():
    raw = bytes(range(34))
    assert di.b58decode(di.b58encode(raw)) == raw
    assert di.b58decode(di.b58encode(b"\x00\x00\x01")) == b"\x00\x00\x01"
    key = issuer_key()
    assert di.multibase_to_public(key.public_multibase) == key.public_bytes
    assert key.public_multibase.startswith("z6Mk")


def test_proof_round_trip_and_tamper_detection():
    key = issuer_key()
    holder = di.did_key_from_seed(hashlib.sha256(b"holder").digest())
    unsigned = vc.device_credential("urn:uuid:1", ISSUER, holder.controller, "d001", "contractor", ["command"],
                                    NOW - 10, NOW + 100, [status_entry(LIST, "revocation", 3)])
    signed = di.add_proof(unsigned, key, "assertionMethod", NOW)
    stack = vc.PythonVerifier()
    assert stack.verify_credential(signed, documents(key), NOW)["verified"]
    assert di.add_proof(unsigned, key, "assertionMethod", NOW) == signed
    changed = dict(signed, credentialSubject=dict(signed["credentialSubject"], deviceId="d002"))
    assert stack.verify_credential(changed, documents(key), NOW)["category"] == "PROOF"
    assert stack.verify_credential(signed, documents(key), NOW + 1000)["category"] == "EXPIRED"
    assert stack.verify_credential(signed, documents(key), NOW - 100)["category"] == "NOT_YET_VALID"
    presentation = di.add_proof(vc.presentation(holder.controller, [signed]), holder, "authentication", NOW, "c1", "building")
    assert stack.verify_presentation(presentation, documents(key), "c1", "building", NOW)["verified"]
    assert stack.verify_presentation(presentation, documents(key), "c2", "building", NOW)["category"] == "PROOF"


def test_bitstring_encoding_matches_the_recommendation():
    bits = Bitstring()
    assert bits.length == MIN_ENTRIES
    bits.set(0, True)
    bits.set(MIN_ENTRIES - 1, True)
    encoded = bits.encode()
    assert encoded.startswith("u") and "=" not in encoded
    raw = gzip.decompress(base64.urlsafe_b64decode(encoded[1:] + "=" * (-len(encoded[1:]) % 4)))
    assert len(raw) == 16384 and raw[0] == 0x80 and raw[-1] == 0x01
    decoded = Bitstring.decode(encoded)
    assert decoded.get(0) and decoded.get(MIN_ENTRIES - 1) and not decoded.get(1)
    with pytest.raises(StatusError):
        bits.get(MIN_ENTRIES)
    with pytest.raises(StatusError):
        Bitstring.decode("zabc")


def test_evidence_rules():
    coverage = {"authority": ISSUER, "epoch": "e", "sequence": 4, "covered_through": NOW}
    listed = list_credential(LIST, ISSUER, "revocation", Bitstring(), NOW, NOW + 300, 5000, coverage)
    evidence = Evidence(listed, NOW + 1)
    assert evidence.sequence == 4 and evidence.covered_through == pytest.approx(NOW) and evidence.ttl == 5.0
    assert evidence.status(status_entry(LIST, "revocation", 5)) is False
    with pytest.raises(StatusError):
        evidence.status(status_entry(LIST, "suspension", 5))
    short = list_credential(LIST, ISSUER, "revocation", Bitstring(8192), NOW, NOW + 300, 5000, coverage)
    with pytest.raises(StatusError):
        Evidence(short, NOW)
    forged = list_credential(LIST, ISSUER, "revocation", Bitstring(), NOW, NOW + 300, 5000,
                             dict(coverage, authority="did:web:other.rcbench.test"))
    with pytest.raises(StatusError):
        Evidence(forged, NOW)


def test_token_signature():
    key = tokens.private_key(hashlib.sha256(b"domain").digest())
    token = tokens.sign({"jti": "a", "exp": NOW + 10, "sub": "did:key:x"}, key, "building")
    assert tokens.verify(token, tokens.public_raw(key))["jti"] == "a"
    other = tokens.private_key(hashlib.sha256(b"other").digest())
    assert tokens.verify(token, tokens.public_raw(other)) is None
    assert tokens.verify(token[:-4] + "AAAA", tokens.public_raw(key)) is None


def test_trace_depends_only_on_seed_and_world_settings():
    first, second = scenario(5, 10, 30.0, 30.0), scenario(5, 10, 30.0, 30.0)
    assert first == second
    assert scenario(6, 10, 30.0, 30.0)["events"] != first["events"]
    roles = [d["role"] for d in first["devices"]]
    assert len(roles) == 10 and len(set(roles)) == 10
    assert first["outages"] == [{"start": 16.0, "end": 46.0, "domains": ["building", "contractor", "provider"]}]
    assert scenario(5, 10, 0.0, 30.0)["outages"] == []


def test_simulator_is_deterministic_and_orders_policies():
    a = simulate(3, "profile", devices=20, outage=30.0)
    b = simulate(3, "profile", devices=20, outage=30.0)
    assert a == b
    assert a["security"]["exposure_max"] < 30.0
    online = simulate(3, "online", devices=20, outage=30.0)
    assert online["security"]["unauthorized_executed"] == 0
    assert online["availability"]["completion"] < a["availability"]["completion"]
    control = simulate(3, "timer_reset", devices=20, outage=30.0)
    assert control["security"]["exposure_max"] > a["security"]["exposure_max"]
