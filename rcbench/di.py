"""Data Integrity proofs with the eddsa-jcs-2022 cryptosuite.

Implements proof creation and verification as specified in W3C Data Integrity
EdDSA Cryptosuites v1.0, Section 3.3, using JSON Canonicalization Scheme
(RFC 8785) and Ed25519 from libsodium (PyNaCl). This module is the Python
verification stack; it shares no code with the Node.js stack.
"""
import copy
import hashlib
from datetime import datetime, timezone

import rfc8785
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

CRYPTOSUITE = "eddsa-jcs-2022"
PROOF_TYPE = "DataIntegrityProof"
MULTIKEY_CONTEXT = "https://w3id.org/security/multikey/v1"
DID_CONTEXT = "https://www.w3.org/ns/did/v1"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_PUB = b"\xed\x01"


class ProofError(Exception):
    """Raised when a proof is malformed or does not verify."""


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        idx = _B58.find(ch)
        if idx < 0:
            raise ProofError("invalid base58 character")
        n = n * 58 + idx
    pad = len(text) - len(text.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


def to_timestamp(epoch_seconds: float) -> str:
    """Format epoch seconds as an XML Schema dateTimeStamp with millisecond precision."""
    dt = datetime.fromtimestamp(round(epoch_seconds, 3), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def from_timestamp(text: str) -> float:
    """Parse an XML Schema dateTimeStamp into epoch seconds."""
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def public_multibase(verify_key_bytes: bytes) -> str:
    return "z" + b58encode(_ED25519_PUB + verify_key_bytes)


def multibase_to_public(multibase: str) -> bytes:
    if not multibase.startswith("z"):
        raise ProofError("public key is not base58btc multibase")
    raw = b58decode(multibase[1:])
    if raw[:2] != _ED25519_PUB or len(raw) != 34:
        raise ProofError("public key is not an Ed25519 Multikey")
    return raw[2:]


class KeyPair:
    """An Ed25519 key pair with its verification method identifier."""

    def __init__(self, controller: str, key_id: str, seed: bytes):
        self.controller = controller
        self.signing_key = SigningKey(seed)
        self.public_bytes = bytes(self.signing_key.verify_key)
        self.public_multibase = public_multibase(self.public_bytes)
        self.id = f"{controller}#{key_id}"

    @property
    def secret_multibase(self) -> str:
        return "z" + b58encode(b"\x80\x26" + bytes(self.signing_key))

    def method(self) -> dict:
        return {"id": self.id, "type": "Multikey", "controller": self.controller,
                "publicKeyMultibase": self.public_multibase}


def did_key_from_seed(seed: bytes) -> KeyPair:
    """Create a did:key key pair; the fragment equals the multibase public key."""
    multibase = public_multibase(bytes(SigningKey(seed).verify_key))
    return KeyPair(f"did:key:{multibase}", multibase, seed)


def did_key_document(did: str) -> dict:
    """Derive the DID document of an Ed25519 did:key identifier."""
    multibase = did.split(":", 2)[2]
    multibase_to_public(multibase)
    vm = f"{did}#{multibase}"
    return {"@context": [DID_CONTEXT, MULTIKEY_CONTEXT], "id": did,
            "verificationMethod": [{"id": vm, "type": "Multikey", "controller": did,
                                    "publicKeyMultibase": multibase}],
            "authentication": [vm], "assertionMethod": [vm]}


def _hash_data(options: dict, document: dict) -> bytes:
    return hashlib.sha256(rfc8785.dumps(options)).digest() + hashlib.sha256(rfc8785.dumps(document)).digest()


def add_proof(document: dict, key: KeyPair, purpose: str, created: float,
              challenge: str | None = None, domain: str | None = None) -> dict:
    """Return a copy of the document secured with an eddsa-jcs-2022 proof."""
    doc = copy.deepcopy(document)
    doc.pop("proof", None)
    options = {"type": PROOF_TYPE, "cryptosuite": CRYPTOSUITE, "created": to_timestamp(created),
               "verificationMethod": key.id, "proofPurpose": purpose}
    if challenge is not None:
        options["challenge"] = challenge
    if domain is not None:
        options["domain"] = domain
    if "@context" in doc:
        options["@context"] = doc["@context"]
    signature = key.signing_key.sign(_hash_data(options, doc)).signature
    doc["proof"] = dict(options, proofValue="z" + b58encode(signature))
    return doc


def verify_proof(document: dict, resolve_key, purpose: str,
                 challenge: str | None = None, domain: str | None = None) -> dict:
    """Verify the single eddsa-jcs-2022 proof on a document.

    resolve_key(verification_method_id, purpose) must return the raw Ed25519
    public key authorized for that purpose, or raise ProofError.
    Returns the proof object on success and raises ProofError otherwise.
    """
    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise ProofError("document must carry exactly one proof object")
    if proof.get("type") != PROOF_TYPE or proof.get("cryptosuite") != CRYPTOSUITE:
        raise ProofError("unsupported proof type or cryptosuite")
    if proof.get("proofPurpose") != purpose:
        raise ProofError("proof purpose mismatch")
    if challenge is not None and proof.get("challenge") != challenge:
        raise ProofError("challenge mismatch")
    if domain is not None and proof.get("domain") != domain:
        raise ProofError("domain mismatch")
    value = proof.get("proofValue")
    if not isinstance(value, str) or not value.startswith("z"):
        raise ProofError("proofValue is not base58btc multibase")
    unsecured = {k: v for k, v in document.items() if k != "proof"}
    options = {k: v for k, v in proof.items() if k != "proofValue"}
    if "@context" in options:
        proof_ctx = options["@context"] if isinstance(options["@context"], list) else [options["@context"]]
        doc_ctx = unsecured.get("@context")
        doc_ctx = doc_ctx if isinstance(doc_ctx, list) else [doc_ctx]
        if doc_ctx[:len(proof_ctx)] != proof_ctx:
            raise ProofError("document context does not start with proof context")
        unsecured["@context"] = options["@context"]
    public = resolve_key(proof.get("verificationMethod"), purpose)
    try:
        VerifyKey(public).verify(_hash_data(options, unsecured), b58decode(value[1:]))
    except BadSignatureError as exc:
        raise ProofError("signature does not verify") from exc
    return proof


def key_resolver(documents: dict):
    """Build a resolve_key function from a map of DID to DID document."""

    def resolve(method_id, purpose):
        if not isinstance(method_id, str) or "#" not in method_id:
            raise ProofError("verification method identifier is malformed")
        did = method_id.split("#", 1)[0]
        doc = documents.get(did)
        if doc is None and did.startswith("did:key:"):
            doc = did_key_document(did)
        if doc is None:
            raise ProofError(f"no DID document for {did}")
        authorized = [m if isinstance(m, str) else m.get("id") for m in doc.get(purpose, [])]
        if method_id not in authorized:
            raise ProofError("verification method is not authorized for this purpose")
        for method in doc.get("verificationMethod", []):
            if method.get("id") == method_id and method.get("controller") == did:
                if method.get("revoked"):
                    raise ProofError("verification method is revoked")
                return multibase_to_public(method["publicKeyMultibase"])
        raise ProofError("verification method not found in DID document")

    return resolve
