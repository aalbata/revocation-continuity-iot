# Continuity profile

This document specifies the implementation profile evaluated by the benchmark. The profile
is a set of integration rules for systems that verify a W3C verifiable credential, exchange
it for a local access token, and admit protected MQTT operations on the basis of that token.
It introduces no cryptographic primitive. Every mechanism it combines (status lists,
freshness limits, token expiry, revocation notification, session termination, and monotonic
version checks) exists in earlier work. The profile states how they must be composed so that
a revocation decision is not lost when authority is translated, moved, resumed, or reloaded.

The code that implements these rules is `rcbench/core.py`. The policy switches are in
`rcbench/policy.py`. The tests in `tests/test_core.py` exercise each rule.

## Pinned credential profile

| Element | Choice |
|---|---|
| Data model | W3C Verifiable Credentials Data Model v2.0, JSON-LD |
| Securing mechanism | Data Integrity proof, cryptosuite `eddsa-jcs-2022` (Ed25519, JSON Canonicalization Scheme) |
| Status | W3C Bitstring Status List v1.0, purposes `revocation` and `suspension`, one list per purpose and issuer, 131,072 one-bit entries |
| Issuer identifiers | `did:web`, with DID documents provisioned as trust anchors and resolved again only from the pinned issuer endpoint |
| Holder identifiers | `did:key` (Ed25519), which needs no resolution |
| Local token | JSON Web Token signed with EdDSA by the issuing edge domain |

Two deviations from the cited specifications are part of this research profile and are
labeled as such wherever they appear.

1. Local resolution of `did:web`. The method resolves over HTTPS at the domain named in the
   identifier. The prototype maps each issuer identifier to a local HTTP endpoint through an
   explicit table in the domain configuration. The identifiers use the reserved `.test`
   top-level domain.
2. Coverage statement. A status list credential carries an additional `coverage` object in
   its credential subject with the fields `authority`, `epoch`, `sequence`, and
   `coveredThrough`. The object states which issuer made the statement, an identifier of the
   list history, a counter that increases with every status change, and the time through
   which the list reflects the issuer's state. It lies inside the signed credential, so the
   list proof binds it to the encoded list. The Recommendation has no such field. The term
   definitions are in `contexts/rcbench-v1.jsonld`.

## Roles and authority

Each issuer is the only authority for the status of the credentials it issued. An edge domain
accepts a status list only if the list identifier is registered for that issuer in the domain
configuration, the list is signed by a key in that issuer's DID document, and the coverage
authority equals the list issuer. A credential is accepted only if its status entries point
to lists of its own issuer and its subject organization is within the scope configured for
that issuer. Resolving a DID document is not a trust decision; the set of accepted issuers
and their scopes is configuration.

Revocation is permanent. An issuer never clears a revocation bit and never assigns a used
index to another credential; a replacement credential has a new identifier and new indices.
Suspension is reversible and uses a separate list. Rotation of an issuer key adds a
verification method to the DID document and leaves the earlier method in place for proofs
made before the rotation. Removal of a verification method invalidates proofs that depend on
it, which is a different event from the revocation of a credential.

## Rules

R1. Binding. Every local token carries the source credential identifier, the source issuer,
the holder identifier, the audience (the issuing domain's broker), the action and topic, the
policy version, the status entries of the source credential, references to the status
evidence that was accepted (list, epoch, sequence, coverage time), the parent token if any,
and the absolute authorization deadline. A session record carries the source credential
identifier, the source issuer, the status entries, the topic, and the deadline.

R2. Deadline inheritance. The deadline of a token is the earliest of the configured token
lifetime, the validity end of the source credential, and the deadline of the status evidence
used for the decision. When a token is derived from a parent token (renewal or handover) and
the evidence is not strictly newer than the evidence referenced by the parent, the deadline is
also limited by the parent's deadline. A derived token can outlive its parent only on the
basis of newer evidence from the issuer.

R3. Evidence age. The age of a status list is measured from its `coveredThrough` time, not
from the time a domain received it and not from `validFrom`, which the data model defines as
the start of validity. Evidence may support a grant until `coveredThrough` plus the freshness
budget minus the declared clock uncertainty, and never after the list's `validUntil`. The
`ttl` value of a list is treated as a refresh hint only.

R4. Persistence and monotonic acceptance. A domain stores the newest accepted list of each
purpose and issuer, its high-water mark (epoch, sequence, coverage time), and its session
table in durable storage. Evidence from a different epoch, or with a lower sequence or
coverage time than the stored mark of the same list, is rejected. Marks of different lists or
issuers are never compared. After a restart the stored state is loaded before any request is
served, and broker sessions without a stored record are removed.

R5. Enforcement at the operation. The executor checks every command before it is executed.
The token signature, audience, topic, and expiry must be valid, the session must still exist,
the current time must not exceed the deadline, and the current evidence must not flag the
source credential. In addition, accepted evidence that flags a credential ends its sessions,
session deadlines are enforced by a timer, and sessions are checked again against current
evidence every five seconds. The decision state is updated before the broker session is
removed, so the executor denies a command even while the broker removal is still queued.

R6. Unknown or stale evidence. If no evidence is stored for a required list, or the stored
evidence is past its deadline and a direct fetch fails, the request is denied with the reason
`evidence_unknown` or `evidence_stale`. The profile does not defer. A holder may supply a
status list with a request; it is treated like any other evidence under R3 and R4 and is
never taken as complete history.

## Enforcement boundary

The protected operation is the execution of a command by the executor. A command counts as
newly admitted when it was sent at or after the revocation commit. A command sent before the
commit and executed after it is reported separately as in flight. The broker is configured
without retained messages and without persistent sessions, and the executor is the only
subscriber of command topics, so no message is delivered from a queue that predates the
session. A device can publish only to its own command topic; a publish to another topic is
refused by the broker.

## Threat model and limits

The issuer, the verification code, the enforcement code, and durable storage are trusted. The
adversary holds the key of a revoked device, replays authentic status lists that predate the
revocation, withholds newer lists, reconnects, reuses earlier tokens and sessions, and moves
between domains. Faults are backhaul outages between domains and issuers, configured delay,
reordered notifications, a gateway restart, clock offset of one domain, and issuer key
rotation. A malicious issuer, rollback of durable storage, clock error beyond the declared
uncertainty, and compromise of a domain are outside the model.

## Conditional exposure limit

Let the commit time be the time at which the issuer records a revocation. Let B be the
freshness budget, D the delay until a domain accepts evidence that covers the commit, u the
declared clock uncertainty, and e the time between two enforcement checks of the same
session (the command period when every command is checked).

Under the assumptions of the threat model, a domain that applies R1 to R6 executes no newly
admitted command of the revoked credential later than min(B, D) + u + e after the commit.

Reasoning. Evidence whose coverage time is at or after the commit flags the credential, so a
grant after the commit can rest only on evidence with an earlier coverage time. By R2 and R3
its deadline is at most that coverage time plus B minus u on the domain clock, which is
earlier than the commit plus B in true time when the clock error is at most u. By R5 the
executor refuses a command after the deadline. If newer evidence is accepted first, R5
refuses commands from that moment. R4 prevents a return to older evidence, including after a
restart. The term e accounts for a command that passed its check immediately before the
deadline or before the newer evidence was stored.

The limit does not hold when an assumption fails. The ablations in the benchmark show three
such cases. Without R2 a token can outlive its evidence by up to the token lifetime. Without
R4 a restarted domain that cannot reach the issuer accepts older evidence again. Without R5
an established session continues until the device disconnects.
