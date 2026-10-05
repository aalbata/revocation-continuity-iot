# Vocabulary of the research extension

The context document `contexts/rcbench-v1.jsonld` defines the terms below. They are used only
by this benchmark and are not part of any W3C Recommendation.

| Term | Used in | Meaning |
|---|---|---|
| <a id="DeviceAuthorizationCredential"></a>`DeviceAuthorizationCredential` | credential type | A credential that authorizes one device to send commands |
| <a id="deviceId"></a>`deviceId` | credential subject | Identifier of the device within the benchmark |
| <a id="organization"></a>`organization` | credential subject | Organization that operates the device; a domain accepts it only from an issuer configured for that organization |
| <a id="allowedAction"></a>`allowedAction` | credential subject | Actions the device may perform; the benchmark uses `command` |
| <a id="coverage"></a>`coverage` | status list subject | Statement by the issuer about the state that the list reflects |
| <a id="authority"></a>`authority` | coverage | Identifier of the issuer that makes the statement; must equal the list issuer |
| <a id="epoch"></a>`epoch` | coverage | Identifier of the list history; sequence numbers are comparable only within one epoch of one list |
| <a id="sequence"></a>`sequence` | coverage | Counter that increases with every status change of the list |
| <a id="coveredThrough"></a>`coveredThrough` | coverage | Time through which the list reflects the issuer's state |
