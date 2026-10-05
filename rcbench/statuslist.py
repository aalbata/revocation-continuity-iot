"""Bitstring Status List v1.0 encoding, credentials, and validation.

The encoded list is the multibase base64url (no padding) form of the GZIP
compressed bitstring, index 0 is the left-most bit, and the list holds at least
131,072 one-bit entries, as required by the W3C Recommendation (Sections 2.2,
3.2 to 3.4). The optional coverage statement is an extension defined by this
study; it sits inside the signed credential subject, so the list proof binds it
to the list content.
"""
import base64
import gzip

from .di import from_timestamp, to_timestamp

V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
MIN_ENTRIES = 131072
EXT_CONTEXT = "https://raw.githubusercontent.com/aalbata/revocation-continuity-iot/main/contexts/rcbench-v1.jsonld"
EXT_NS = "https://github.com/aalbata/revocation-continuity-iot/blob/main/docs/vocabulary.md#"
EXT_CONTEXT_DOCUMENT = {"@context": {
    "@protected": True,
    "coverage": {"@id": EXT_NS + "coverage", "@context": {
        "authority": {"@id": EXT_NS + "authority", "@type": "@id"},
        "epoch": EXT_NS + "epoch",
        "sequence": EXT_NS + "sequence",
        "coveredThrough": {"@id": EXT_NS + "coveredThrough",
                           "@type": "http://www.w3.org/2001/XMLSchema#dateTime"}}},
    "DeviceAuthorizationCredential": EXT_NS + "DeviceAuthorizationCredential",
    "deviceId": EXT_NS + "deviceId",
    "organization": EXT_NS + "organization",
    "allowedAction": EXT_NS + "allowedAction",
}}


class StatusError(Exception):
    """Raised with a W3C status error name when a list cannot be used."""

    def __init__(self, name: str, detail: str = ""):
        super().__init__(f"{name}: {detail}" if detail else name)
        self.name = name


class Bitstring:
    def __init__(self, length: int = MIN_ENTRIES, data: bytes | None = None):
        self.length = length
        self.data = bytearray(data) if data is not None else bytearray((length + 7) // 8)

    def set(self, index: int, value: bool) -> None:
        if not 0 <= index < self.length:
            raise StatusError("RANGE_ERROR", f"index {index}")
        byte, bit = divmod(index, 8)
        mask = 0x80 >> bit
        self.data[byte] = (self.data[byte] | mask) if value else (self.data[byte] & ~mask)

    def get(self, index: int) -> bool:
        if not 0 <= index < self.length:
            raise StatusError("RANGE_ERROR", f"index {index}")
        byte, bit = divmod(index, 8)
        return bool(self.data[byte] & (0x80 >> bit))

    def __eq__(self, other) -> bool:
        return isinstance(other, Bitstring) and self.length == other.length and self.data == other.data

    __hash__ = None

    def encode(self) -> str:
        packed = gzip.compress(bytes(self.data), mtime=0)
        return "u" + base64.urlsafe_b64encode(packed).rstrip(b"=").decode()

    @classmethod
    def decode(cls, encoded: str) -> "Bitstring":
        if not isinstance(encoded, str) or not encoded.startswith("u"):
            raise StatusError("MALFORMED_VALUE_ERROR", "encodedList is not base64url multibase")
        body = encoded[1:]
        try:
            raw = gzip.decompress(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except Exception as exc:
            raise StatusError("MALFORMED_VALUE_ERROR", "encodedList cannot be decoded") from exc
        return cls(len(raw) * 8, raw)


def list_credential(list_id: str, issuer: str, purpose: str, bits: Bitstring, valid_from: float,
                    valid_until: float, ttl_ms: int, coverage: dict | None = None) -> dict:
    """Build an unsigned BitstringStatusListCredential."""
    subject = {"id": list_id + "#list", "type": "BitstringStatusList", "statusPurpose": purpose,
               "encodedList": bits.encode(), "ttl": ttl_ms}
    context = [V2_CONTEXT]
    if coverage is not None:
        context.append(EXT_CONTEXT)
        subject["coverage"] = {"authority": coverage["authority"], "epoch": coverage["epoch"],
                               "sequence": coverage["sequence"],
                               "coveredThrough": to_timestamp(coverage["covered_through"])}
    return {"@context": context, "id": list_id,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"], "issuer": issuer,
            "validFrom": to_timestamp(valid_from), "validUntil": to_timestamp(valid_until),
            "credentialSubject": subject}


def status_entry(list_id: str, purpose: str, index: int) -> dict:
    return {"id": f"{list_id}#{index}", "type": "BitstringStatusListEntry", "statusPurpose": purpose,
            "statusListIndex": str(index), "statusListCredential": list_id}


def entries_of(credential: dict) -> list:
    status = credential.get("credentialStatus", [])
    return status if isinstance(status, list) else [status]


class Evidence:
    """Parsed content of a status list credential whose proof has been verified."""

    __slots__ = ("issuer", "list_id", "purpose", "valid_from", "valid_until", "ttl", "epoch",
                 "sequence", "covered_through", "bits", "received_at", "size_bytes", "source")

    def __init__(self, credential: dict, received_at: float, size_bytes: int = 0, source: str = "fetch"):
        subject = credential.get("credentialSubject", {})
        if "BitstringStatusListCredential" not in credential.get("type", []):
            raise StatusError("STATUS_VERIFICATION_ERROR", "not a status list credential")
        if subject.get("type") != "BitstringStatusList":
            raise StatusError("STATUS_VERIFICATION_ERROR", "subject is not a BitstringStatusList")
        issuer = credential.get("issuer")
        self.issuer = issuer["id"] if isinstance(issuer, dict) else issuer
        self.list_id = credential.get("id")
        self.purpose = subject.get("statusPurpose")
        self.valid_from = from_timestamp(credential["validFrom"])
        self.valid_until = from_timestamp(credential["validUntil"])
        self.ttl = subject.get("ttl", 0) / 1000.0
        self.bits = Bitstring.decode(subject.get("encodedList"))
        if self.bits.length < MIN_ENTRIES:
            raise StatusError("STATUS_LIST_LENGTH_ERROR", f"{self.bits.length} entries")
        coverage = subject.get("coverage")
        if coverage is not None:
            if coverage.get("authority") != self.issuer:
                raise StatusError("STATUS_VERIFICATION_ERROR", "coverage authority is not the list issuer")
            self.epoch = coverage["epoch"]
            self.sequence = int(coverage["sequence"])
            self.covered_through = from_timestamp(coverage["coveredThrough"])
        else:
            self.epoch, self.sequence, self.covered_through = None, None, None
        self.received_at = received_at
        self.size_bytes = size_bytes
        self.source = source

    def status(self, entry: dict) -> bool:
        """Return the status bit for a credentialStatus entry of the same list and purpose."""
        if entry.get("statusListCredential") != self.list_id:
            raise StatusError("STATUS_VERIFICATION_ERROR", "entry refers to a different list")
        if entry.get("statusPurpose") != self.purpose:
            raise StatusError("STATUS_VERIFICATION_ERROR", "status purpose mismatch")
        try:
            index = int(entry.get("statusListIndex"))
        except (TypeError, ValueError) as exc:
            raise StatusError("MALFORMED_VALUE_ERROR", "statusListIndex") from exc
        return self.bits.get(index)
