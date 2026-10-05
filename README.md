# Revocation continuity benchmark for decentralized IoT identity

This repository contains the benchmark, the continuity profile, the simulator, and the per-run
results of the article "Revocation Continuity for Decentralized IoT Identity Across Edge
Domains" by Ali Al Bataineh and Lakshmana Kumar Ramasamy (Computer Information Science, Higher
Colleges of Technology, Abu Dhabi, United Arab Emirates).

The benchmark measures how long a revoked device can still act after its issuer has recorded
the revocation. A device presents a W3C verifiable credential to an edge gateway, receives a
local access token, opens an MQTT session, publishes commands, hands over to another edge
domain, and meets a gateway restart and a backhaul outage. Nine integration policies run on the
same lifecycle traces. The primary measure is the time from the revocation commit at the issuer
to the last unauthorized command that was sent after the commit and executed.

Everything runs as native local processes. No container runtime, cloud service, or special
hardware is used. All identifiers and traces are synthetic.

## Contents

| Path | Purpose |
|---|---|
| `rcbench/core.py` | Gateway and executor decision logic shared by the live prototype and the simulator |
| `rcbench/policy.py` | The nine policies as switches over that logic |
| `rcbench/di.py`, `rcbench/statuslist.py`, `rcbench/vc.py` | Python verification stack: `eddsa-jcs-2022` proofs, Bitstring Status List, credential profile |
| `node_verifier/server.mjs` | Node.js verification stack built on the Digital Bazaar libraries |
| `rcbench/issuer.py`, `rcbench/domain.py`, `rcbench/devices.py`, `rcbench/broker.py` | Live components: issuers, edge domains (gateway and executor), devices, Mosquitto administration |
| `rcbench/trace.py`, `rcbench/world.py`, `rcbench/batch.py` | Seeded lifecycle traces, one run, a manifest of runs |
| `rcbench/metrics.py`, `rcbench/analysis.py` | Per-run measures and run-level bootstrap summaries |
| `rcbench/sim.py` | Discrete-event simulator that drives `core.py` |
| `rcbench/fixtures.py`, `fixtures/` | Interoperability fixtures processed by both stacks |
| `configs/` | Run manifests: pilot, primary matrix, sensitivity sweeps |
| `scripts/` | Manifest generation, interoperability run, collection, calibration, simulation, summaries, figures, tables |
| `results/` | Per-run measures (`runs/*.jsonl`), simulation runs, calibration, interoperability table, sample traces, and `manifest.json`, the single source of every reported number |
| `figures/` | Figures as vector PDF and PNG |
| `docs/PROFILE.md` | Specification of the continuity profile, threat model, and conditional exposure limit |
| `docs/vocabulary.md`, `contexts/rcbench-v1.jsonld` | Terms of the research extension used in credentials |
| `tests/` | Deterministic tests of the decision rules, formats, traces, and simulator |
| `reproduce.py` | Fast path, simulation path, and full path of reproduction |

## Requirements

- Windows 11 (the experiments were run on an Intel Core Ultra 7 155U with 16 GB of memory)
- Python 3.12.10 with the packages pinned in `requirements.txt`
- For live runs only: Node.js 24.19.0 with the packages pinned in `node_verifier/package-lock.json`,
  and Mosquitto 2.1.2 with its Dynamic Security plugin on the `PATH` (or its folder in the
  environment variable `MOSQUITTO_DIR`)

## Installation (PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest tests -q
```

For live runs, also install the Node.js packages:

```powershell
cd node_verifier
npm ci
cd ..
```

## Reproduction

Fast path. Rebuild the manifest, tables, and figures from the shipped per-run files and compare
them with the shipped outputs. This takes about three minutes and needs Python only.

```powershell
python reproduce.py
```

Simulation path. Also rerun the simulation study from the shipped calibration. The simulator is
deterministic, so `results/sim_runs.jsonl` is reproduced exactly. This takes about half an hour.

```powershell
python reproduce.py --simulate
```

Full path. Rerun the live experiments, then calibration, simulation, summaries, and figures. The
1,650 final runs took about ten hours on the machine named above, with six to eight parallel
runs for the conditions with 10 devices and two for the conditions with 100 devices. Live
timings vary between runs, so measured values differ slightly from the shipped ones.

```powershell
python reproduce.py --full --raw .\raw
```

A single live run, for example the continuity profile with a 30-second outage:

```powershell
python -m rcbench.world --out .\raw\example --policy profile --outage 30 --seed 1
python -m rcbench.metrics .\raw\example
```

## Policies

| Key | Policy | Status source | Token lifetime | Applied to live sessions | Check at each command | Durable state |
|---|---|---|---|---|---|---|
| `online` | Online checks | Issuer consulted for every decision | 60 s | Expiry | Online status | No |
| `cached` | Cached status | Own cache, age from receipt | 30 s | Expiry | Token validity | No |
| `shortlived` | Short-lived grants | Own cache, age from receipt | 5 s | Expiry | Token validity | No |
| `coordinated` | Coordinated practice | Cache and holder-supplied lists with an ordering check held in memory, age from `validFrom`, notifications | 60 s, inherited deadline | Expiry, revocation, recheck every 5 s | Token validity | No |
| `profile` | Continuity profile | As above, age from the coverage statement | 60 s, inherited deadline | Expiry, revocation, recheck every 5 s | Token, session, deadline, current evidence | Yes |
| `no_inherit` | Profile without inheritance | As profile | 60 s | As profile | As profile | Yes |
| `no_persist` | Profile without persistence | As profile | 60 s, inherited deadline | As profile | As profile | No |
| `no_session` | Profile without session enforcement | As profile | 60 s, inherited deadline | None | None | Yes |
| `timer_reset` | Timer-reset control (negative control) | Cache and holder-supplied lists, age from receipt, no ordering | 60 s | Expiry | Token validity | No |

All caching policies use the same freshness budget (30 s unless varied), the same refresh
interval (5 s with the 30 s budget), and the same configured backhaul round-trip time (50 ms
unless varied). The token lifetimes of `cached` and `shortlived` were chosen on the pilot seeds
as described in `rcbench/policy.py`. The ablation `no_session` removes all enforcement after
admission. The timer-reset control differs from the profile in several settings and is not a
single-rule ablation.

The primary matrix and all sensitivity conditions except `python-*` use the Node.js verification
stack. The `python-*` conditions repeat the five main policies at outages of 0 and 30 s on the
Python stack. In live runs the selected stack verifies the proofs and validity periods of
presentations, device credentials, and status list credentials. Status lists are decoded and
read by `rcbench/statuslist.py` under both settings, and the status check of the Digital Bazaar
library runs on the interoperability fixtures only.

## Measures

Definitions are implemented in `rcbench/metrics.py`. The run is the unit of analysis.

| Field | Definition | Unit |
|---|---|---|
| `exposure_max` | Largest value, over the revoked devices of a run, of the time from the revocation commit to the last executed command that was sent at or after the commit | s |
| `exposure_admit_max` | Same, for commands delivered by the broker to the executor whether or not they were executed | s |
| `unauthorized_executed` | Commands of revoked devices sent at or after the commit and executed | count |
| `unauthorized_fraction` | `unauthorized_executed` divided by all attempts of revoked devices after the commit, including bypass probes | share |
| `in_flight_executed` | Commands sent before the commit and executed after it, reported separately | count |
| `censored` | A revoked device was still executing commands within 1.5 s of the end of observation, so exposure is a lower bound | flag |
| `completion` | Benign commands executed within 1 s, divided by all benign commands that were due, including those that could not be sent | share |
| `latency_ms_median`, `latency_ms_p95` | Time from publish to execution of benign commands completed within 1 s; summaries are means of per-run percentiles | ms |
| `backhaul_bytes` | Request and response bodies of status fetches by gateways, notifications, and key resolution between domains and issuers; the periodic list downloads by devices are not counted | bytes |
| `renewals` | Granted token renewals | count |
| `memory_mb` | Peak resident memory per process of the run | MB |

Summaries in `results/manifest.json` are means over runs with 95 percent percentile bootstrap
intervals (10,000 resamples of runs, fixed seed). Paired comparisons resample per-seed
differences.

## Results

<!-- results:start -->
Generated by `scripts/report.py` from `results/manifest.json`. Values are means over independent runs
with 95 percent bootstrap intervals over runs in brackets.

### Time from revocation commit to the last newly executed unauthorized command (s)

| Policy | Outage 0 s | Outage 5 s | Outage 30 s | Outage 120 s |
|---|---|---|---|---|
| Online checks | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] |
| Cached status | 30.3 [29.9, 30.6] | 30.4 [30.2, 30.8] | 48.0 [47.9, 48.1] | 48.0 [47.9, 48.2] |
| Short-lived grants | 7.7 [7.4, 8.0] | 7.6 [7.1, 8.0] | 26.1 [25.8, 26.4] | 26.2 [25.9, 26.5] |
| Coordinated practice | 0.3 [0.2, 0.3] | 4.2 [2.5, 5.9] | 28.5 [28.3, 28.7] | 28.4 [28.3, 28.6] |
| Continuity profile | 0.3 [0.2, 0.4] | 0.5 [0.4, 0.7] | 24.0 [23.7, 24.2] | 23.8 [23.5, 24.1] |
| Profile without inheritance | 0.3 [0.2, 0.3] | 0.5 [0.4, 0.7] | 24.9 [24.6, 25.1] | 80.7 [80.3, 81.0] |
| Profile without persistence | 0.3 [0.2, 0.4] | 3.9 [2.3, 5.6] | 28.6 [28.4, 28.9] | 28.6 [28.4, 28.8] |
| Profile without session enforcement | 78.1 [77.8, 78.4] (censored in 30 of 30) | 78.1 [77.8, 78.4] (censored in 30 of 30) | 100.1 [99.8, 100.4] (censored in 30 of 30) | 139.1 [138.8, 139.4] (censored in 30 of 30) |
| Timer-reset control | 68.4 [68.2, 68.6] (censored in 30 of 30) | 68.4 [68.2, 68.6] (censored in 30 of 30) | 90.4 [90.2, 90.6] (censored in 30 of 30) | 129.4 [129.2, 129.6] (censored in 30 of 30) |

### Benign commands completed within one second (percent)

| Policy | Outage 0 s | Outage 5 s | Outage 30 s | Outage 120 s |
|---|---|---|---|---|
| Online checks | 99.4 [99.3, 99.4] | 92.7 [92.6, 92.9] | 73.3 [73.2, 73.4] | 19.8 [19.7, 19.9] |
| Cached status | 99.3 [99.3, 99.3] | 99.1 [99.0, 99.2] | 94.7 [94.6, 94.7] | 46.4 [46.3, 46.4] |
| Short-lived grants | 98.7 [98.6, 98.8] | 98.5 [98.4, 98.6] | 94.4 [94.3, 94.5] | 36.0 [35.8, 36.2] |
| Coordinated practice | 99.2 [99.2, 99.3] | 99.1 [99.1, 99.2] | 97.9 [97.8, 98.0] | 38.2 [38.1, 38.3] |
| Continuity profile | 99.5 [99.5, 99.6] | 99.2 [99.2, 99.3] | 97.9 [97.9, 98.0] | 38.2 [38.2, 38.3] |
| Profile without inheritance | 99.5 [99.5, 99.5] | 99.3 [99.2, 99.3] | 99.4 [99.4, 99.4] | 70.4 [70.4, 70.5] |
| Profile without persistence | 99.2 [99.2, 99.3] | 99.1 [99.1, 99.2] | 97.9 [97.8, 98.0] | 38.2 [38.1, 38.3] |
| Profile without session enforcement | 99.6 [99.6, 99.7] | 99.3 [99.3, 99.4] | 99.4 [99.4, 99.4] | 99.5 [99.5, 99.6] |
| Timer-reset control | 91.6 [91.6, 91.6] | 91.3 [91.3, 91.4] | 89.0 [88.9, 89.0] | 86.6 [86.6, 86.6] |

### Cost at an outage of 30 s

| Policy | Unauthorized share (percent) | Command latency p95 (ms) | Backhaul traffic (kB per run) | Token renewals per run | Runs | Failed |
|---|---|---|---|---|---|---|
| Online checks | 0.0 [0.0, 0.0] | 105.93 [104.88, 106.94] | 2973 [2952, 2993] | 8.0 [8.0, 8.0] | 30 | 0 |
| Cached status | 24.2 [24.2, 24.3] | 1.37 [1.29, 1.44] | 331 [329, 332] | 20.7 [20.3, 21.1] | 30 | 0 |
| Short-lived grants | 16.8 [16.6, 16.9] | 1.68 [1.47, 1.99] | 335 [333, 336] | 226.9 [226.1, 227.7] | 30 | 0 |
| Coordinated practice | 23.2 [23.0, 23.3] | 1.39 [1.32, 1.46] | 323 [321, 325] | 45.0 [44.5, 45.5] | 30 | 0 |
| Continuity profile | 19.8 [19.6, 19.9] | 1.44 [1.36, 1.54] | 321 [319, 324] | 43.6 [43.4, 43.7] | 30 | 0 |
| Profile without inheritance | 21.4 [21.2, 21.5] | 1.58 [1.35, 1.99] | 322 [321, 324] | 10.0 [10.0, 10.0] | 30 | 0 |
| Profile without persistence | 23.2 [23.0, 23.3] | 1.42 [1.35, 1.49] | 326 [324, 329] | 45.3 [44.8, 45.8] | 30 | 0 |
| Profile without session enforcement | 91.0 [90.9, 91.0] | 1.29 [1.22, 1.37] | 322 [321, 324] | 33.8 [33.6, 33.9] | 30 | 0 |
| Timer-reset control | 66.3 [66.3, 66.4] | 1.35 [1.28, 1.42] | 324 [323, 325] | 10.6 [10.4, 10.7] | 30 | 0 |

### Interoperability fixtures

26 of 28 fixtures gave the same verdict in both stacks.

- `credential-inline-context` (extension terms given as an inline context object): Python accept, Node.js reject, expected accept
- `status-list-short` (list has fewer than 131,072 entries): Python error, Node.js clear, expected error

### Simulation against live measurement

Across 38 uncensored conditions the mean absolute difference in exposure is 0.51 s (largest 3.88 s). Across 46 conditions the mean absolute difference in completion is 0.44 percentage points (largest 4.23).
<!-- results:end -->

## Scope and limits

Every run that was started under the final configuration is included. One earlier attempt at the
sensitivity manifest with eight parallel runs was discarded in full before analysis, because
100-device runs exhausted local sockets and 8 of 220 runs failed to start; the manifest was then
run again unchanged, with 100-device runs two at a time (`rcbench/batch.py`).

The benchmark devices do not present their credential again while a broker session with an
expired token stays open. This lowers benign completion in the timer-reset control and in the
conditions with a session lifetime of 300 s, and it does not affect the other conditions, in
which a session ends with its token.

The evaluation is a software study on one laptop computer. Delay and outage are injected at the
application layer. A handover is an application-level move between edge domains and does not
represent a radio handover. Simulation results are model time, not measured throughput. The
coverage statement in status list credentials and the local resolution of `did:web` identifiers
are research deviations described in `docs/PROFILE.md`.

## License

MIT, see `LICENSE`. The Node.js dependencies keep their own licenses (BSD-3-Clause for the
Digital Bazaar libraries).
