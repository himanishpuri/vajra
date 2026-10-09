# Vajra

Inline intrusion prevention with automated response, built on Suricata.

Vajra runs Suricata inline, so packets matching its rules are dropped before
they reach the host. Alongside it, a response engine reads every alert,
decides whether the source should be blocked outright, and applies the block
with iptables or nftables. Each decision is logged, every block gets a
report, and all events are available as one live stream.

The rule the whole thing is built around: **Vajra never cuts the host off from
its own network.** Loopback, the host's own address, its gateway and its DNS
resolvers are never blocked. [Safety](#safety) lists exactly how that is
enforced.

[Discord](https://discord.gg/gZTJfUujX) ·
[Contributing](CONTRIBUTING.md) ·
[Code of Conduct](CODE_OF_CONDUCT.md) ·
[Security](SECURITY.md)

## Project status

Vajra is an early stage project, maintained by the Ergane Foundation and not
yet released. The inline pipeline (Suricata, the response engine, the unified
log and the event stream) is built and has been run on development machines.
Nothing has run in production. The machine learning components exist but are unvalidated, and
are labelled experimental below.

## How it works

```
traffic ─► iptables NFQUEUE ─► Suricata (inline, rules/local.rules)
                                   │ logs/eve.json
          ┌────────────────────────┼──────────────────────────┬──────────────────────┐
          ▼                        ▼                          ▼                      ▼
   SOAR engine              Unified logger             Event stream             Kafka bridge
   decide → block IP        logs/unified_events.json   ws://127.0.0.1:8000      (optional)
   (iptables / nftables)                               /ws/logs
```

Suricata inspects traffic from an NFQUEUE and writes its events to
`logs/eve.json`. Each Python service tails that file on its own. The SOAR
engine blocks the source of an alert when the alert is critical or high
severity, when its signature names an attack class such as SQL injection or
scanning, or when an ML model or behaviour analytics flags it with high
confidence. [docs/architecture.md](docs/architecture.md) has the details.

## Safety

| Situation | What Vajra does |
| --- | --- |
| Alert source is loopback, the host itself, its gateway or a DNS resolver | Never blocks it |
| Alert source is in `--allow` or `VAJRA_ALLOWLIST` | Never blocks it |
| Connection started by any of those addresses | Suricata passes it without inspection, so no rule drops it. If the gateway NATs inbound traffic, connections forwarded through it look like the gateway and are not inspected either |
| Started with `--dry-run` | Logs each decision as `not_enforced` and leaves the firewall alone |
| No firewall backend, for example on macOS | Logs the decision as `not_enforced` rather than reporting a block |
| Event stream and inference API | Listen on `127.0.0.1` only, unless `VAJRA_API_HOST` says otherwise |
| Demo HTTP target | Serves only `logs/www`, never the repository |

Live mode still runs as root, inserts NFQUEUE rules and enables IP
forwarding. Use a disposable Linux VM.

## Capabilities

| Capability | Status |
| --- | --- |
| Inline IPS with custom Suricata rules | Implemented |
| Automated IP blocking with allowlist and dry-run mode | Implemented |
| Unified event log (Suricata, SOAR and ML) | Implemented |
| Live event stream over WebSocket | Implemented |
| Rule-based user behaviour analytics | Implemented |
| Kafka export of alerts | Experimental |
| ML model management and inference API | Experimental |
| Scapy deep packet inspection | Experimental |
| Encrypted-traffic, anomaly and fingerprinting engines | Experimental, not wired in |
| AI-generated Suricata rules (Google Gemini) | Experimental, not wired in |
| Federated learning (Flower) | Experimental, not wired in |
| DPDK packet capture | Roadmap, does not build yet |

## Quickstart

You need a Linux VM (Ubuntu or Debian), Python 3.10 or later, root access and
`make`.

```bash
git clone https://github.com/Ergane-Foundation/vajra.git
cd vajra
make install                            # Suricata and system packages
make setup                              # virtualenv and editable install
sudo ./scripts/start.sh --dry-run       # start without enforcing blocks
```

From another machine, send some attack traffic at the VM:

```bash
python3 tools/attack_simulator.py --target <vm-ip>
```

Then look at what Vajra decided:

```bash
make status
tail -f logs/soar_actions.log
```

When the decisions look right, restart without `--dry-run` to enforce them.
Stop everything with `make stop`.

On macOS, install Suricata with Homebrew (`brew install suricata`), then run
`make setup` and `make start`. Suricata runs in passive mode there, so Vajra
detects but cannot block.

## Configuration

Options for `scripts/start.sh` and `scripts/start_macos.sh`:

| Option | Description |
| --- | --- |
| `--dry-run` | Log SOAR block decisions without changing the firewall |
| `--no-http` | Do not start the demo HTTP target |
| `--no-api` | Do not start the inference API |

Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `VAJRA_INTERFACE` | auto-detected | Network interface to protect |
| `VAJRA_ALLOWLIST` | | Comma separated addresses or networks that are never blocked |
| `VAJRA_API_HOST` | `127.0.0.1` | Address the event stream and inference API bind to |
| `HTTP_PORT` | `80` (`8080` on macOS) | Port for the demo HTTP target |
| `ML_MODELS_DIR` | `models` | Directory the SOAR engine loads models from |

The SOAR engine can also run on its own, for example to replay a saved
`eve.json` without root:

```bash
python -m vajra.soar.engine --file-mode --eve path/to/eve.json --dry-run --allow 10.0.0.0/8
```

## Services and ports

| Service | Port | Started by default |
| --- | --- | --- |
| Suricata (NFQUEUE 0) | | yes |
| Event stream | 8000 | yes |
| Inference API | 8001 | yes, `--no-api` to skip |
| Demo HTTP target | 80, 8080 on macOS | yes, `--no-http` to skip |
| Kafka bridge to `localhost:9092` | | yes, idle unless Kafka is running |

The endpoints are described in [docs/api-reference.md](docs/api-reference.md).

## Optional features

The core install is kept small. Optional features are Python extras:

| Extra | Adds |
| --- | --- |
| `ml` | TensorFlow, PyTorch and imbalanced-learn for the bundled models |
| `dpi` | Scapy packet inspection |
| `fl` | Flower for federated learning |
| `rulegen` | Google Gemini client for AI rule generation |
| `perf` | Matplotlib and psutil for the performance harnesses |

Install one with `pip install -e ".[ml]"`, or all of them with
`make setup-full`. What is known about each bundled model is in
[models/README.md](models/README.md).

## Repository layout

```
src/vajra/           Python package
  soar/              Response engine: alert, decision, firewall block, reports
  pipeline/          eve.json consumers: event stream, unified logger, Kafka bridge
  detection/         Behaviour analytics used by the SOAR engine
  ml/                Model loading and prediction management
  inspection/        Packet inspection (Scapy, DPDK feature feed)
  api/               Inference API and its client
  experimental/      Engines, AI rule generation, federated learning
rules/               Suricata rules
config/suricata/     Suricata configuration
models/              Bundled model files
scripts/             Install, start, stop, status and diagnostics
native/dpdk/         DPDK packet processor (C++)
tests/perf/          Resource consumption and load test harnesses
tools/               Attack simulator, live monitor, WebSocket client, benchmark
docs/                Architecture and API reference
```

## Limitations

- Blocks are permanent. Nothing expires them, and stopping the pipeline does
  not remove them. Remove a block by hand with `iptables -D` or `nft delete`.
- The nftables backend adds to a set named `inet filter blocked_ips`, which
  none of the scripts create yet. Without it, nftables blocks fail.
- With iptables, the SOAR engine appends its DROP rules after the NFQUEUE
  rules. Whether they take effect depends on how the chain is evaluated, and
  this has not been verified.
- One matching alert is enough to block a source. There is no threshold,
  cooldown or rate limit yet.
- The bundled models have no documented training data or evaluation, and some
  are fed inputs that do not match what they were trained on.
- Live mode runs every component as root.
- `logs/eve.json` and `logs/unified_events.json` grow without rotation.
- There is no automated test suite yet.

## Roadmap

Planned or being considered, none of it built yet:

- Expiring blocks and an `unblock` command
- Correct nftables and iptables setup for blocks, created and removed by the scripts
- Thresholds, cooldowns and rate limits on blocking
- An offline demo with Docker Compose and pcap replay that needs no root
- Unit tests and CI
- Validated models with documented training data
- A dashboard
- The DPDK capture path

Issues labelled `good first issue` are the best place to start.

## Development

```bash
make setup
source venv/bin/activate
make lint
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, conventions
and how pull requests are reviewed.

## Maintainers

Vajra is maintained by the [Ergane Foundation](https://github.com/Ergane-Foundation).

- Agampreet Singh ([@agam1092005](https://github.com/agam1092005))
- Namanmeet Singh ([@NamanmeetSingh](https://github.com/NamanmeetSingh))

## Licence

Vajra is licensed under the [Apache License 2.0](LICENSE).

Vajra runs Suricata (GPL-2.0) as a separate, unmodified program. The
optional `dpi` extra installs Scapy (GPL-2.0), and the optional Kafka
integration uses Apache Kafka (Apache 2.0). Neither is part of the default
installation.
