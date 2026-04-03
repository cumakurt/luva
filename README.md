# Luva

**Luva** is a **passive** offline analyzer for industrial control and SCADA network captures (`.pcap`, `.pcapng`, and `.gz`-wrapped captures). It reads files from disk only—no live sniffing, no injection, no interaction with the plant network.

[Türkçe README →](README.tr.md)

<p align="center">
  <img src="img/main.png" alt="Luva interactive HTML report — Executive tab with KPI cards and charts" width="900"/>
</p>

<p align="center"><em>Figure: Executive summary in the generated HTML report (click KPIs for drill-down). Luva analyzes PCAP/PCAPNG offline; CLI runs also emit JSON, CSV, GraphML, and optional communication-map / NDJSON exports.</em></p>

## What it does

| Area | Capabilities |
|------|----------------|
| **Protocols** | Deep packet inspection–style parsing for **eleven** built-in OT/ICS protocols (see table below), over captured Ethernet/IP traffic (via **Scapy**). |
| **Assets** | Discovers endpoints (IP, MAC), infers **device roles** (PLC, HMI, RTU, gateway, engineering station, etc.), tracks **open ports**, **ICS-specific fields** (e.g. Modbus unit IDs, S7 rack/slot, DNP3 address hints), **vendor hints** from MAC OUI, communication partners, byte/packet counts, and a **heuristic risk score** with human-readable risk factors. |
| **Flows** | Builds **bidirectional flows** (5-tuple–style keys), ties ICS frames to flows, and aggregates statistics for reporting. |
| **Topology** | Constructs a **logical network/service graph** (assets and relationships) and exports **GraphML** (default **`topology_<UTC-stamp>.graphml`** on the CLI) for **Gephi**, **yEd**, or **NetworkX**. |
| **Detection** | YAML-driven **rule engine** with Modbus, S7, DNP3, and generic rules; events carry **severity** (INFO → CRITICAL) and **category** (protocol, behavior, network, policy). Statistical helpers support richer analysis in code paths that use them. |
| **Reporting** | **JSON** (full structured report), **CSV** (assets, flows, anomalies, **audit findings**), **HTML** (single-file summary dashboard), plus **GraphML** as above. **CLI runs** append a **UTC timestamp** to each artifact basename so consecutive scans do not overwrite files (see [Output files](#output-files-cli-defaults)). |
| **Deep survey** | **`statistics.deep_survey`**: capture window, port/DNS/HTTP aggregates, TLS guesses, **`cleartext_hints`**, **`ics_port_visibility`**, banners, timelines — and **OT-sensitive cleartext** heuristics (see below). |
| **Threat-oriented roll-ups** | **`statistics.threat_patterns`**: passive hints such as Modbus write flows, S7 critical op families, IT remote-access ports on flows, scanner/credential-flavoured strings, ARP/broadcast noise, duplicate TCP payload fingerprints, sequential multi-target ICS access — surfaced in JSON/HTML (**Threat patterns** tab) and cross-referenced from **`audit_workbook`**. |
| **OT cleartext exposure** | Packet-level detection of **unencrypted industrial payloads** (Modbus, IEC-104, S7, DNP3, OPC UA HEL, EtherNet/IP, BACnet/IP, SNMP community *redacted*, HTTP with OT tokens, generic ICS TCP ports). Exposed as **`deep_survey.cleartext_ot_sensitive`**; **Network & cleartext** HTML table; rolls into **`pentest_insights`** and audit finding **`CLEARTEXT_OT_PAYLOAD`**. [Details](#deep-packet-survey-and-ot-cleartext-hints). |
| **Audit & evidence** | **Chain-of-custody** hashes per input file in JSON metadata; structured **`audit_workbook`** (findings, MITRE hints, remediation, passive exposure index); **Audit & pentest** tab and **`audit_findings.csv`**. See [Audit and evidence](#audit-and-evidence-for-security-assessors). |
| **EKS & Purdue** | Embeds a full **ICS/EKS component taxonomy** (field → enterprise), **heuristic EKS tags per asset**, **Purdue / ISA-95 level reference**, **IEC 62443 conduit note**, and **OT segmentation** principles — in **`analysis_report.json`** under **`eks`** and in the HTML **EKS & Purdue** tab. |
| **Safety model** | **Passivity guard**: analysis targets regular capture files; the design avoids live-capture interfaces. |
| **Privacy** | **`anonymize_ips`** (deterministic IPv4 → `10.x.x.x` in exports) and **`mask_payload`** (redact raw payload / hex in nested JSON, **including OT cleartext sample fields**: hex previews, HTTP excerpts, SNMP redaction strings) on **`AnalysisConfig`** and CLI **`--anonymize-ips`** / **`--mask-payload`**. |

## CLI (`luva.py` or `luva` command)

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python luva.py capture.pcapng
# or, after editable install:
luva capture.pcapng
```

Multiple captures are merged into one run:

```bash
python luva.py a.pcap b.pcapng
```

By default: **full** pipeline, all **eleven** built-in parsers, minimum severity **INFO**, outputs under **`./reports/`**. While the pipeline runs, **short progress lines** are printed to **stdout** as `[Luva] …` (rules, packet pass, anomalies, topology, GraphML path); **packet counts** still go to **stderr** unless disabled. Use **`--quiet`** to hide the `[Luva]` lines and the export banner. Useful options:

| Option | Description |
|--------|-------------|
| `-o`, `--output-dir` | Output directory (default: `reports`) |
| `--mode` | `full`, `anomaly-only`, `asset-only`, `topology-only` |
| `--min-severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--protocols` | Comma-separated slugs, e.g. `modbus,s7` |
| `--custom-rules` | Extra YAML rule directory |
| `--formats` | Comma-separated outputs: `json`, `csv`, `html`, `communication-map`, `anomalies-ndjson`, or `all` (default) |
| `--chunk-size` | Max packets per input file (`0` = full capture; useful for quick samples) |
| `--compare-baseline` | Path to a **previous full JSON** report (e.g. `analysis_report_20260115_083022.json`); adds `statistics.baseline_diff` to the new JSON |
| `--anomaly-subset-pcap` | Write packets referenced by anomalies (`packet_number` + source file name) to this PCAP |
| `--anonymize-ips` / `--mask-payload` | Privacy for shared reports |
| `--no-graph` | Skip topology GraphML export |
| `--graph-path` | Base GraphML path; a **UTC run timestamp** is inserted **before the extension** (same suffix as other artifacts) |
| `--no-progress` | Disable packet progress on stderr |
| `-q`, `--quiet` | No `[Luva] …` phase lines on stdout and no “Writing exports…” banner |
| `-v`, `--verbose` | INFO-level logging |

Example:

```bash
luva capture.pcapng -o ./out --mode asset-only --protocols modbus --anonymize-ips
luva capture.pcapng --formats json,anomalies-ndjson --chunk-size 50000
```

Validate rule YAML (exit `0` if every rule in `*.yaml` parses; non-zero on errors):

```bash
luva validate-rules /path/to/rules
luva validate-rules luva/detection/rules
```

### Output files (CLI defaults)

Each CLI run generates a **UTC suffix** like **`_YYYYMMDD_HHMMSS`** (e.g. `_20260403_153045`) and appends it to every export **basename** before the extension. JSON **`metadata.report_filename_suffix`** repeats that suffix when non-empty.

| Output | Description |
|--------|-------------|
| `analysis_report_<UTC>.json` | Metadata, summary, assets, flows, topology, anomalies, statistics — includes **`statistics.deep_survey`**, **`statistics.threat_patterns`**, **`statistics.event_timeline`**, optional **`statistics.baseline_diff`**, **`statistics.audit_workbook`**, **`statistics.pentest_insights`** |
| `assets_<UTC>.csv` | Tabular assets |
| `ot_assets_<UTC>.csv` | OT/ICS-classified assets (ICS ports, parser labels, field hints, inferred roles) |
| `flows_<UTC>.csv` | Tabular flows |
| `anomalies_<UTC>.csv` | Tabular detection events |
| `audit_findings_<UTC>.csv` | Structured audit workbook rows (IDs, severity, MITRE IDs, remediation, standards refs) |
| `anomalies_<UTC>.ndjson` | One JSON object per line (SIEM-friendly); enable with `--formats` |
| `<capture-stem>_<UTC>.html` or `analysis_report_<UTC>.html` | HTML report (single input → capture stem; multiple inputs → `analysis_report`): **Executive** (clickable KPI drill-downs), **Protocols & exposure**, **OT & comms**, **Assessment**, **Inventory (EKS)**, **OT inventory**, **Audit & pentest**, **Threat patterns**, **Network & cleartext**, **ICS flows**, matrix, **Anomalies**, **Diagnostics** |
| `communication_map_<UTC>.html` | **Interactive OT communication map** (D3 embedded from `luva/output/static/` when shipped; otherwise jsDelivr CDN): hosts (role, vendor, risk), directed links with **per-session protocol**, L4 ports, packet/byte counts, write flags; ICS-only filter; zoom/pan |
| `topology_<UTC>.graphml` | Graph for external tools |

**Library / tests:** If you construct **`AnalysisConfig`** with the default **`report_filename_suffix=""`**, reporters keep **legacy names** (`analysis_report.json`, `assets.csv`, …) for stable automation.

## Analysis modes (CLI and Python API)

The CLI **`--mode`** flag mirrors `AnalysisConfig.mode`:

- **`full`** — assets, flows, topology, anomalies  
- **`anomaly-only`** — skip topology/graph export path  
- **`asset-only`** — assets only; skips anomaly rules execution where the pipeline allows  
- **`topology-only`** — topology-focused path  

## Supported ICS / OT protocols

| Protocol | Slug | Typical ports | What it is used for |
|----------|------|-----------------|---------------------|
| **Modbus/TCP** | `modbus` | 502 | Register/coil read–write between PLCs, HMIs, and field devices; very common on industrial Ethernet. |
| **S7comm** | `s7` | 102 | Siemens S7 session and cyclic data; engineering and PLC I/O. |
| **DNP3** | `dnp3` | 20000 | SCADA/outstation style messaging (TCP adaptation of serial DNP3). |
| **OPC UA** | `opcua` | 4840 | Client–server (and pub/sub) access to tags, alarms, methods, and historian-style data. |
| **EtherNet/IP** | `enip` | 44818 | CIP encapsulation; Allen-Bradley / Rockwell-style I/O and explicit messaging. |
| **IEC 60870-5-104** | `iec104` | 2404 | Power-system telecontrol (APCI/ASDU) over TCP. |
| **BACnet/IP** | `bacnet` | 47808 | Building automation: objects, properties, alarms, scheduling (UDP/TCP; BVLC + APDU subset). |
| **MQTT** | `mqtt` | 1883, 8883, 8884, 9001 | Lightweight publish/subscribe; IIoT gateways and cloud-linked SCADA. |
| **SNMP** | `snmp` | 161, 162 | Monitoring and management (Get/Set, traps); network gear and some embedded devices. |
| **Omron FINS** | `omron_fins` | 9600 | Factory Interface Network Service over TCP/UDP (passive framing subset). |
| **GE SRTP** | `ge_srtp` | 18245, 18246 | Service Request Transport Protocol envelope (passive subset). |

**Default enabled slugs** (same eleven): `modbus`, `s7`, `dnp3`, `opcua`, `enip`, `iec104`, `bacnet`, `mqtt`, `snmp`, `omron_fins`, `ge_srtp`. Use **`--protocols`** to restrict the set.

The port registry still lists other OT-related ports (e.g. PROFINET, Foundation Fieldbus HSE) as hints only; they do not have dedicated parsers in this package unless listed in the table above.

## Custom rules

Use **`--custom-rules /path/to/dir`** on the CLI, or set **`AnalysisConfig.custom_rules_dir`** in code. Files must match the built-in rule schema (see `luva/detection/rules/*.yaml`). Check files with **`luva validate-rules DIR`** before deploying custom rules.

## Python API (library use)

```python
from pathlib import Path
from luva.core.config import AnalysisConfig, AnalysisMode, utc_report_filename_suffix
from luva.core.pipeline import AnalysisPipeline

cfg = AnalysisConfig(
    input_files=[Path("capture.pcapng")],
    mode=AnalysisMode.FULL,
    export_formats=("json", "csv"),  # omit keys you do not need
    chunk_size=0,
    compare_baseline=None,  # e.g. Path("prior_report.json")
    anomaly_subset_pcap=None,  # e.g. Path("anomaly_hits.pcap")
    report_filename_suffix=utc_report_filename_suffix(),  # optional: match CLI timestamped names
    quiet=False,  # set True to silence [Luva] stdout lines during run()
)
result = AnalysisPipeline(cfg).run()
# result.assets, result.flows, result.anomalies, result.to_dict()
```

## Audit and evidence for security assessors

Passive runs include artifacts aimed at **reviewers, auditors, and pentesters** working from offline captures:

| Artifact | Where | Purpose |
|----------|--------|---------|
| **Input integrity** | `metadata.input_evidence` | Per file: path, filename, size, **SHA-256** of bytes **as stored on disk** (e.g. a `.pcap.gz` is hashed compressed). `metadata.evidence_integrity_note` states how to use this for **chain of custody** (re-hash after copy or archival). |
| **Audit workbook** | `statistics.audit_workbook` | Structured findings (`AUD-001` …) with severity, category, narrative, evidence summary, **MITRE ATT&CK** mapping *hints*, remediation text, and **IEC 62443 / NIST SP 800-82** style references; **passive exposure index** (0–100, weighted severities — **not** a CVSS score); samples of **ICS write** flows; **public IPv4** assets; assets with **22 / 3389 / 5900**; cross-reference to `pentest_insights`. |
| **HTML** | **Audit & pentest** tab | Human-readable summary of hashes, scope/limitations, findings tables, and surface samples. |
| **CSV** | `audit_findings_<UTC>.csv` (CLI) or `audit_findings.csv` if `report_filename_suffix` is empty | Flat export of workbook findings alongside the other CSVs. |

MITRE and IEC/NIST references are **heuristic labels from passive traffic** — always confirm against your **architecture**, **CMDB**, and **threat model** before treating them as confirmed techniques or compliance gaps.

## Deep packet survey and OT cleartext hints

The pipeline always builds **`statistics.deep_survey`** from passive metadata: capture span, unique IPs/MACs, top TCP/UDP ports (with registry labels), per-minute timeline, DNS qnames, HTTP `Host` headers, **`cleartext_hints`** (SSH/FTP/telnet/SNMP/HTTP-like counts), **`banner_samples`**, **`tls`** heuristics, and **`ics_port_visibility`**.

**`cleartext_ot_sensitive`** adds **bounded, packet-level** rows (default up to **40** deduplicated samples) when payloads look like **unencrypted OT traffic** (TLS ClientHello is skipped). Categories include, among others: **Modbus TCP** on 502 (MBAP + function code; write-family FCs scored higher), **IEC-104** APCI-shaped frames, **S7** TPKT on 102, **DNP3** on 20000, **OPC UA** `HEL` on 4840, **EtherNet/IP** register session on 44818, **BACnet/IP** BVLC on UDP 47808, **SNMPv1/v2c** community field (**masked** in the sample, e.g. `p*******c`), **HTTP** requests/responses containing OT-related tokens, and **generic non-TLS payload on other ICS-associated TCP ports** from the port registry.

Each sample includes endpoints, a short **summary**, and a **truncated hex preview** or text excerpt. **`hits_by_category`** counts every matching packet; samples are deduplicated by category and flow key.

- **JSON**: `statistics.deep_survey.cleartext_ot_sensitive`
- **HTML**: **Network & cleartext** → *OT-sensitive cleartext (heuristic)*
- **`pentest_insights`**: passive finding and **`summary_counts.cleartext_ot_packet_hits`**
- **`audit_workbook`**: **`CLEARTEXT_OT_PAYLOAD`** when hits or samples exist

Use **`--mask-payload`** before sharing exports to strip `evidence_preview_hex`, `http_context_excerpt`, and `snmp_community_redacted`. These rules are **heuristic** (TCP segmentation, tunnelling, and non-standard ports can cause false negatives or noise); validate suspicious rows in the PCAP.

## Requirements

- **Python 3.10+**
- Dependencies: **Scapy**, **NetworkX**, **Rich**, **Typer**, **PyYAML**, **Jinja2**, **NumPy** (see `pyproject.toml`)

### Very large captures (e.g. multi‑GB / ~20 GB)

Luva streams packets from disk (no full capture in RAM). Per-flow state uses **fixed-memory** statistics (Welford) instead of storing every packet size or inter-arrival time. Timeline buckets are **per minute**; DNS/HTTP cardinality is capped. **By default** (`AnalysisConfig` / CLI with no size overrides), exported flows, communication matrices, and **`communication_graph`** edges are **not capped** (`max_flows_export`, `max_communication_matrix_ips`, and `max_communication_graph_edges` default to **`0`** = include everything — full reports). Set positive limits on `AnalysisConfig` if you need smaller JSON/HTML/CSV. Progress prints to **stderr** every 2 M packets by default (`show_progress`, `progress_packet_interval`); phase summaries use **stdout** as `[Luva] …` unless `quiet=True`. **`.pcap.gz`** still needs enough **disk** space to hold the decompressed temp file.

## Samples

Example captures live under `luva/sample/`. Many `.pcap` files may be **Git LFS pointers** until you run `git lfs pull`; some `.pcapng` files are regular binaries.

### Public protocol smoke captures (`public_pcaps/`)

Small **third-party** PCAPs (Wireshark SampleCaptures + [w3h/icsmaster](https://github.com/w3h/icsmaster)) cover **Modbus, S7, DNP3, OPC UA, EtherNet/IP, and IEC 104** in one pass; use your own captures to exercise **BACnet, MQTT, and SNMP** parsers.

```bash
./public_pcaps/fetch_public_pcaps.sh   # optional: re-download from the network
python luva.py public_pcaps/*.pcap
```

Attribution and upstream URLs are listed in [`public_pcaps/SOURCES.txt`](public_pcaps/SOURCES.txt).

## Development

```bash
pip install -e ".[dev]"
pytest luva/tests ot_baseline/tests
ruff check luva ot_baseline luva.py baseline.py
mypy luva
```

**CI:** [GitHub Actions](.github/workflows/ci.yml) runs **pytest**, **ruff**, and **mypy** on Python 3.10, 3.12, and 3.13 for pushes and pull requests to `main` / `master`.

**Contributing:** See [`CONTRIBUTING.md`](CONTRIBUTING.md). **Security contact:** [`SECURITY.md`](SECURITY.md).

### Checklist for publishing on GitHub

| Item | Location |
|------|-----------|
| Open-source license | [`LICENSE`](LICENSE) (AGPL-3.0-only, referenced in `pyproject.toml`) |
| Project metadata & URLs | [`pyproject.toml`](pyproject.toml) (`Homepage`, `Repository`) |
| Ignore local / build noise | [`.gitignore`](.gitignore) |
| Automated tests & lint | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| Contributor & security notes | [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) |
| README screenshot | [`img/main.png`](img/main.png) |

## Author

Developed by **Cuma KURT** — [cumakurt@gmail.com](mailto:cumakurt@gmail.com)

- [LinkedIn](https://www.linkedin.com/in/cuma-kurt-34414917/)
- [GitHub repository](https://github.com/cumakurt/luva)

## License

Luva is licensed under the **GNU Affero General Public License v3.0 only** (**AGPL-3.0-only**). See the [`LICENSE`](LICENSE) file. If you run a **modified** version as a **network service**, AGPL requires you to offer corresponding source to users interacting with that service.
