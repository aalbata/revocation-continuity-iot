"""Credential profile and the two verification stacks.

The pinned profile is the W3C Verifiable Credentials Data Model v2.0 in JSON-LD,
secured with Data Integrity proofs using the eddsa-jcs-2022 cryptosuite, with
Bitstring Status List v1.0 entries. PythonVerifier is the stack written for this
study; NodeVerifier calls the service in node_verifier/server.mjs, which wraps
the Digital Bazaar libraries. Both return the same result shape:
{"verified": bool, "category": str, "messages": [str]} where category is one of
OK, PROOF, MALFORMED, NOT_YET_VALID, EXPIRED.
"""
import json
import urllib.request

from . import di
from .statuslist import EXT_CONTEXT, V2_CONTEXT, Evidence, StatusError, entries_of

CREDENTIAL_TYPE = "DeviceAuthorizationCredential"


def device_credential(credential_id: str, issuer: str, holder: str, device_id: str, organization: str,
                      actions: list, valid_from: float, valid_until: float, status_entries: list) -> dict:
    """Build an unsigned device authorization credential."""
    return {"@context": [V2_CONTEXT, EXT_CONTEXT], "id": credential_id,
            "type": ["VerifiableCredential", CREDENTIAL_TYPE], "issuer": issuer,
            "validFrom": di.to_timestamp(valid_from), "validUntil": di.to_timestamp(valid_until),
            "credentialSubject": {"id": holder, "deviceId": device_id, "organization": organization,
                                  "allowedAction": actions},
            "credentialStatus": status_entries}


def presentation(holder: str, credentials: list) -> dict:
    """Build an unsigned verifiable presentation."""
    return {"@context": [V2_CONTEXT], "type": ["VerifiablePresentation"], "holder": holder,
            "verifiableCredential": credentials}


def issuer_of(credential: dict) -> str:
    issuer = credential.get("issuer")
    return issuer.get("id") if isinstance(issuer, dict) else issuer


def _result(category: str = "OK", message: str = "") -> dict:
    return {"verified": category == "OK", "category": category, "messages": [message] if message else []}


def _structure_error(document: dict, required_type: str) -> str:
    context = document.get("@context")
    if not isinstance(context, list) or not context or context[0] != V2_CONTEXT:
        return "first context is not the credentials v2 context"
    types = document.get("type")
    types = types if isinstance(types, list) else [types]
    if required_type not in types:
        return f"type does not include {required_type}"
    return ""


class PythonVerifier:
    """Verification stack implemented in this package."""

    name = "python"

    def verify_credential(self, credential: dict, documents: dict, now: float) -> dict:
        problem = _structure_error(credential, "VerifiableCredential")
        if not problem and not issuer_of(credential):
            problem = "issuer is missing"
        if not problem and not isinstance(credential.get("credentialSubject"), (dict, list)):
            problem = "credentialSubject is missing"
        if problem:
            return _result("MALFORMED", problem)
        try:
            proof = di.verify_proof(credential, di.key_resolver(documents), "assertionMethod")
        except di.ProofError as exc:
            return _result("PROOF", str(exc))
        if proof["verificationMethod"].split("#", 1)[0] != issuer_of(credential):
            return _result("PROOF", "proof was not created by the issuer")
        try:
            if "validFrom" in credential and di.from_timestamp(credential["validFrom"]) > now:
                return _result("NOT_YET_VALID", "validFrom is in the future")
            if "validUntil" in credential and di.from_timestamp(credential["validUntil"]) < now:
                return _result("EXPIRED", "validUntil is in the past")
        except (TypeError, ValueError):
            return _result("MALFORMED", "validity period is not a dateTimeStamp")
        return _result()

    def verify_presentation(self, vp: dict, documents: dict, challenge: str, domain: str, now: float) -> dict:
        problem = _structure_error(vp, "VerifiablePresentation")
        if problem:
            return _result("MALFORMED", problem)
        try:
            proof = di.verify_proof(vp, di.key_resolver(documents), "authentication", challenge, domain)
        except di.ProofError as exc:
            return _result("PROOF", str(exc))
        if vp.get("holder") and proof["verificationMethod"].split("#", 1)[0] != vp["holder"]:
            return _result("PROOF", "proof was not created by the holder")
        credentials = vp.get("verifiableCredential", [])
        for credential in credentials if isinstance(credentials, list) else [credentials]:
            inner = self.verify_credential(credential, documents, now)
            if not inner["verified"]:
                return inner
        return _result()

    def check_status(self, credential: dict, lists: list, documents: dict, now: float) -> dict:
        """Verify each supplied status list credential and read the bits for the credential."""
        by_id = {item.get("id"): item for item in lists}
        statuses = []
        for entry in entries_of(credential):
            listed = by_id.get(entry.get("statusListCredential"))
            if listed is None:
                return {"verified": False, "messages": ["STATUS_RETRIEVAL_ERROR"], "statuses": []}
            checked = self.verify_credential(listed, documents, now)
            if not checked["verified"]:
                message = "STATUS_VERIFICATION_ERROR: " + "; ".join(checked["messages"])
                return {"verified": False, "messages": [message], "statuses": []}
            try:
                if issuer_of(listed) != issuer_of(credential):
                    raise StatusError("STATUS_VERIFICATION_ERROR", "issuers do not match")
                bit = Evidence(listed, now).status(entry)
            except StatusError as exc:
                return {"verified": False, "messages": [str(exc)], "statuses": []}
            statuses.append({"purpose": entry["statusPurpose"], "status": bit})
        return {"verified": True, "messages": [], "statuses": statuses}


class NodeVerifier:
    """Client of the Node.js verification service (Digital Bazaar libraries)."""

    name = "node"

    def __init__(self, port: int, timeout: float = 10.0):
        self.base = f"http://127.0.0.1:{port}"
        self.timeout = timeout

    def _post(self, route: str, body: dict) -> dict:
        data = json.dumps(body).encode()
        request = urllib.request.Request(self.base + route, data=data, headers={"content-type": "application/json"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read())

    @staticmethod
    def _with_key_documents(documents: dict, *signed: dict) -> dict:
        merged = dict(documents)
        for item in signed:
            method = (item.get("proof") or {}).get("verificationMethod", "")
            did = method.split("#", 1)[0]
            if did.startswith("did:key:") and did not in merged:
                merged[did] = di.did_key_document(did)
        return merged

    def verify_credential(self, credential: dict, documents: dict, now: float) -> dict:
        return self._post("/verify-credential", {"credential": credential, "now": di.to_timestamp(now),
                                                 "documents": self._with_key_documents(documents, credential)})

    def verify_presentation(self, vp: dict, documents: dict, challenge: str, domain: str, now: float) -> dict:
        return self._post("/verify-presentation", {
            "presentation": vp, "challenge": challenge, "domain": domain, "now": di.to_timestamp(now),
            "documents": self._with_key_documents(documents, vp)})

    def check_status(self, credential: dict, lists: list, documents: dict, now: float) -> dict:
        return self._post("/check-status", {"credential": credential, "statusListCredentials": lists,
                                            "documents": documents})

    def issue(self, document: dict, key: di.KeyPair, purpose: str, created: float,
              challenge: str | None = None, domain: str | None = None) -> dict:
        return self._post("/issue", {
            "document": document, "purpose": purpose, "challenge": challenge, "domain": domain,
            "created": di.to_timestamp(created),
            "key": {"id": key.id, "controller": key.controller, "publicKeyMultibase": key.public_multibase,
                    "secretKeyMultibase": key.secret_multibase}})
