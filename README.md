# Device Annotation Framework (DAF)

DAF is a modular Python framework for **annotating network flow datasets** with device-specific metadata based on IP or MAC addresses. 
It supports parallel annotators, detectors, configurable thresholds, logging, and dataset and annotation data export.

DAF performs both **initial annotation** and **reannotation** using saved JSON state. Final annotations are derived by voting and merging outputs from multiple annotators.

## Features

- Modular annotator architecture
- Parallel or sequential annotator execution
- Annotation merging and conflict handling
- Reannotation support
- Per-IP metadata and annotation logs
- Full dataset output with appended annotations
- Detailed annotation statistics
- JSON export of IP annotation state

## Installation

Install with `pip`:

```sh
python3 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install -e .        # install in editable mode
```

### Requirements

- Python 3.9+  
- `pandas`, `pyyaml`, and `requests`  
- Annotator modules (in `./annotators` or specified path)  

## Quick Start

This framework includes example configuration and dataset files, allowing you to get started quickly.

For real annotation tasks, make sure to provide your own annotator databases and update the configuration file accordingly.

Example usage:

```
./daf.py --config ../examples/basic/daf_config_example.yml --dataset ../examples/basic/example_dataset.csv --logfile ../examples/basic/daf_example.log
```

Output files will be saved next to the selected dataset. A timestamped example
using 15-minute windows is available under `examples/windowing`.

## Outputs

- `*_annotated.csv`: Dataset with appended annotations  
- `*_ip_data.json`: Per-IP annotation export  
- Logs to console or file  
- Printed annotation statistics  

## Arguments

- `--config` (required): Path to YAML configuration file  
- `--dataset`: Path to CSV dataset with flow records  
- `--logfile`: True (console), filename (file logging), or False (disable logging)  
- `-d`: CSV delimiter. Default: ','  
- `--reannotation`: Load data from previous annotation JSON file  

## Configuration

The configuration file uses YAML format. Each module, including `daf.py`, has its own configuration section. The path to a module can be set manually or as `auto` if the module is located in the `annotators_path` or `detectors_path` directories. If a module is present in one of these directories but lacks a configuration section, a warning will be issued.

Example:
```
daf:
  ip_ranges: ...
  src_ip_field: ...
  ...

nat_detector:
  enabled: True
  path: auto
  field: ...

hand_annotator:
  ...
```

### DAF Module Configuration Fields

- **`daf`**
  - `ip_ranges`: IP filtering strategy (`"ALL"`, list, etc.)  
  - `src_ip_field`, `dst_ip_field`: Field names for source/destination IP  
  - `src_port_field`, `dst_port_field`: Field names for source/destination port  
  - `annotators_path`: Folder with annotator modules  
  - `detectors_path`: Folder with detector modules  
  - `min_annotation_count`: Minimum consistent samples per label  
  - `min_annotators_count`: Minimum agreeing annotators to accept label  
  - `threads`: Use multi-threading for annotation  
  - `export_full_annotation`: Include all fields in output dataset  
  - `data_export`: Export IP-level data as JSON  
  - `windowing`: Optionally run the unchanged DAF pipeline over time windows

- **`module`**
  - `enabled`: `True` / `False`  
  - `path`: `/.../module.py` or `auto`


## How It Works

1. **Input**: CSV flow dataset with IP-level fields.
2. **Modular Annotation**: Annotator modules process flows grouped by source IP, outputting partial device annotations (e.g., OS, class, group).
3. **Merging**: Annotations are merged using a voting mechanism (`min_annotation_count`, `min_annotators_count`).
4. **Finalization**: Results are stored per IP and optionally exported.
5. **Reannotation**: Optionally loads a saved annotation file and only annotates new/unseen IPs.

### Windowed processing

DAF can run its existing module pipeline once per time or row window and combine
the completed IP results using majority voting:

```yaml
daf:
  windowing:
    enabled: true
    type: time
    size: 15min
    timestamp_field: TIME_FIRST
    consensus: majority
```

For fixed row windows, use `type: rows` and a positive integer `size`. Time-windowed
CSV input must be sorted by `timestamp_field`; window bounds are `[start, end)`.
Missing annotation values abstain from majority voting.

When `data_export` is enabled, `_ip_data.json` includes the final consensus and
the compact result from each window. Time-windowed reannotation appends only
previously unseen IP and bucket combinations before recalculating consensus.
Row-window reannotation is not supported because row positions are not stable.


## Annotation Taxonomy

### Device Type

| `group` | `_class` |
| ----------- | ----------- |
| `server`  | web server, mail server, dns server, dhcp server, ntp server, syslog server, vpn server, honeypot, data server, git server, metacentrum, bot, authentication server, smtp server, proxy server, multipurpose server, development server |
| `net-device`  | core router, wifi router, firewall |
| `end-device`  | workstation, mobile, tablet, wifi client, printer, voip, ups, payment terminal, ip camera, tv, smartwearable |

### Operating Systems

| `os-family` | `os-type` |
| ----------- | ----------- |
| `windows`  | windows, server |
| `macos`  | macos, ios, ipados |
| `linux`  | debian, fedora, cisco ios, chrome os, oracle, ... |
| `unix`  | freebsd |
| `android`  | android |

## Final Annotation Logic

- A tag is accepted if it appears at least `min_annotation_count` times.
- If more than one tag is found, no annotation is assigned. If two tags are found and one meets `min_annotation_count` while the other appears only once, conflict is logged as `one_miss`.
- If `hand_annotator` is present, it overrides other values. Discrepancies are tracked in `hand_miss`.
- Multi-device detection or NAT is flagged via `multi_device`.

## Annotators

Currently implemented:

- `sni_annotator`
- `shodan_annotator`
- `useragent_annotator`
- `mac_annotator`
- `hostname_annotator`
- `hand_annotator`
- `nat_detector` (simple temporary implementation)

### Adding a New Module

Each annotator must implement:

```python
def annotate(ip_addresses: list, config: dict, ip_data_dict: dict) -> None
```

Enable annotators in the config:

```yaml
hand_annotator:
    enabled: True
    path: auto
    db: "./.../.csv"
```

The path to a module can be set manually or as `auto` if the module is located in the `annotators_path` or `detectors_path` directories.

## Reannotation

DAF supports reannotation using previously saved IP annotation data (`*_ip_data.json`). This allows reuse of computed annotations across datasets, settings, or time periods.

To run reannotation:

```sh
python3 daf.py --config daf_config.yml --reannotation dataset_ip_data.json
python3 daf.py --config daf_config.yml --reannotation dataset_ip_data.json --dataset new_flows.csv
```

- If `--dataset` is provided, DAF compares dataset IPs to those in the annotation file.
- Existing annotations are reused for known IPs.
- Annotators run only for new/unseen IPs.
- If no new IPs are found, no module is started.

### Use Cases

1. **Configuration tuning**: Run annotation multiple times with different settings of `min_annotator_count`; reannotation avoids repeating expensive operations.
2. **Large dataset partitioning**: Split large datasets and run DAF sequentially; reannotation remembers previously annotated IPs.
3. **Time-sensitive annotations**: For time-dependent annotators(`hostname_annotator`,`shodan_annotator`, etc.), reuse previous annotation data for consistency.

## Printed Statistics

After annotation, DAF prints a summary:

- **Total IPs**: Count of processed IP addresses.
- **Successfully annotated IPs**: IPs with a non-empty final annotation.
- **Missing/incomplete annotations**:  
    - No consensus among annotators  
    - Conflicting labels or insufficient support  
- **Per-tag distribution**: Count of IPs per OS family, type, class, group.
- **Per-annotator statistics**:  
    - Number of annotations per module  
    - Tag frequency per annotator  
- **Special conditions**:  
    - `multi_device`: IPs with conflicting annotations (possible NAT)  
    - `hand_miss`: IPs where hand annotator override the result  
    - `one_miss`: Valid label discarded due to one conflicting outlier

These statistics help debug and improve annotator performance.

## Disclaimer

While DAF is designed to support both IP and MAC address-based annotation, **full MAC address support is not yet implemented**.  
Currently, using MAC addresses requires:

1. ip.py
Line 69: self.ip_addr = ipaddress.ip_address(ip_addr) -> self.ip_addr = ip_addr
2. Disable `shodan_annotator` and `hostname_annotator`
3. Insert SRC_MAC field name into configuration field `src_ip_field`

 
Improved and official MAC support is planned for a future release.


## License

BSD-3-Clause  
(C) 2025 CESNET, z.s.p.o.
