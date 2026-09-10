# Device Annotation Framework (DAF)

DAF is a modular Python framework for **annotating network flow datasets** with device-specific metadata based on IP or MAC addresses. 
It supports parallel annotators, detectors, configurable thresholds, logging, and dataset and annotation data export.

DAF performs both **initial annotation** and **reannotation** using saved JSON state. Final annotations are derived by voting and merging outputs from multiple annotators.

## Features

- Modular, class-based annotator and detector architecture
- IP-based and flow-based annotators
- Parallel or sequential annotator execution
- Annotation merging and conflict handling
- Windowed processing of large datasets with window voting
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

Example usage, run from the `src` directory:

```sh
./daf.py --config ../examples/basic/daf_config_example.yml --dataset ../examples/basic/example_dataset.csv --logfile ../examples/basic/daf_example.log
```

Output files are saved next to the selected dataset. A timestamped example using
15-minute windows is available under `examples/windowing` (`examples/windowing/run.sh`).

## Outputs

- `*_annotated.csv`: Dataset with appended annotations  
- `*_ip_annotation_list.csv`: Final (and optionally per-annotator) annotation of every IP  
- `*_ip_data.json`: Per-IP annotation export  
- Logs to console or file  
- Printed annotation statistics  

## Arguments

- `--config` (required): Path to YAML configuration file  
- `--dataset`: Path to CSV dataset with flow records  
- `--logfile`: `True` (console, default), a filename (file logging), or `False` (disable logging)  
- `-d`: CSV delimiter. Default: ','  
- `--reannotation`: Load data from previous annotation JSON file  

## Configuration

The configuration file uses YAML format. Each module, including `daf.py`, has its own configuration section. The path to a module can be set manually or as `auto` if the module is located in the `annotators_path` or `detectors_path` directories. If a module is present in one of these directories but lacks a configuration section, a warning will be issued.

Example:

```yaml
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
  - `ip_ranges`: IP filtering strategy (`"ALL"` or path to a CSV with IP addresses and networks)  
  - `src_ip_field`, `dst_ip_field`: Field names for source/destination IP  
  - `src_port_field`, `dst_port_field`: Field names for source/destination port  
  - `annotators_path`: Folder with annotator modules  
  - `detectors_path`: Folder with detector modules  
  - `os_taxonomy_path`, `device_taxonomy_path`: Paths to the taxonomies  
  - `min_annotation_count`: Minimum consistent samples per label  
  - `min_annotators_count`: Minimum agreeing annotators to accept label  
  - `threads`: Use multi-threading for annotation  
  - `export_full_annotation`: Include all fields in output dataset  
  - `data_export`: Export IP-level data as JSON  
  - `windowing`: Optional windowed processing, see [Windowed processing](#windowed-processing)  

- **`module`**
  - `enabled`: `True` / `False`  
  - `path`: `/.../module.py` or `auto`

## How It Works

1. **Input**: CSV flow records. IPs are selected from the source (and optionally destination) IP column and filtered by `ip_ranges`.
2. **Modular Annotation**: Annotator and detector modules process the IPs and output partial device annotations (e.g., OS, class, group) or multi-device evidence.
3. **Merging**: Annotations are merged using a voting mechanism (`min_annotation_count`, `min_annotators_count`).
4. **Finalization**: Results are stored per IP and optionally exported.
5. **Reannotation**: Optionally loads a saved annotation file and only annotates new/unseen IPs.

## Architecture

DAF is object oriented. The entry point `daf.py` (`main()`) parses the arguments, sets
up logging, loads the configuration with `ConfigLoader` and runs a `DAFApplication`
created with it. The application loads the taxonomies and the modules, selects the
runner (windowed or not) and starts the annotation process:

| File | Classes |
| --- | --- |
| `daf.py` | `DAFApplication` (loads modules, selects and starts the runner), `main()` |
| `config.py` | `ConfigLoader`, `Requirement`, `Configurable`, `ConfigError` |
| `core.py` | `DAFModule`, `IPAnnotator`, `FlowAnnotator`, `Detector` (module base classes) |
| `loader.py` | `ModuleLoader` (module discovery, import and initialization) |
| `pipeline.py` | `ModuleRunner` (threads, error handling), `DAFRunner`, `WindowedDAFRunner` |
| `windows.py` | `WindowConfig`, `RowWindowIterator`, `TimeWindowIterator`, `WindowVoting`, `WindowResolver`, window results |
| `dataset.py`, `ip_ranges.py` | `FlowDataset`, `IPSelector` (dataset IPs filtered by `ip_ranges`) |
| `ip.py`, `annotation.py` | `IP`, `IPCollection`, `IPDataFile`, `Annotation` |
| `output.py`, `stats.py` | `OutputPaths`, `AnnotationListExporter`, `DatasetAnnotator`, `AnnotationStatistics` |
| `taxonomy_checker.py` | `TaxonomyChecker` |

### Configuration requirements

The configuration stays a plain dictionary, but every class declares the keys it reads
as `Requirement` objects and checks them when it is created (`Configurable`):

```python
REQUIREMENTS = (
    Requirement("db_file", str, path="file"),              # required, file must exist
    Requirement("timeout", (int, float), default=5, minimum=0),
    Requirement("mode", str, default="passive", choices=("passive", "active")),
    Requirement("xml_file", str, required_if={"mode": "passive"}),
)
```

Missing keys get their defaults, invalid values stop DAF at startup with a message
such as `hand_annotator.db: file does not exist: rules.csv`. The framework classes
declare their keys of the `daf` section in the same way, e.g. `IPSelector` requires
`src_ip_field` and `ip_ranges`, `ModuleLoader` the module directories and
`WindowConfig` the `daf.windowing` section.

### Module kinds

Every annotator and detector is a class derived from one of the module kinds in
`core.py`:

| Base class | Input | Windowed processing | Modules |
| --- | --- | --- | --- |
| `IPAnnotator` | IP address only | Runs **once** for every IP | `hand_annotator`, `hostname_annotator`, `shodan_annotator` |
| `FlowAnnotator` | Flows of the IP | Runs in **every window** | `sni_annotator`, `useragent_annotator`, `mac_annotator` |
| `Detector` | Flows of the IP | Runs in **every window** | `nat_detector` |

Modules are placed in folders by their kind:

```
src/annotators/ip/      hand_annotator, hostname_annotator, shodan_annotator, ...
src/annotators/flow/    sni_annotator, useragent_annotator, mac_annotator
src/detectors/          nat_detector (detectors are flow-based)
```

IP-based annotators receive every selected IP, including IPs without source flows.
Flow-based annotators receive only IPs with source flows and validate the dataset
columns they need before the run. A detector does not create an annotation: its
result is stored in `IP.data[<detector>]` and positive results are added to
`IP.multi_device`.

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

## Windowed processing

DAF can process a dataset in time or row windows instead of loading it to memory at once:

```yaml
daf:
  windowing:
    enabled: true
    type: time            # time or rows
    size: 15min           # pandas duration (or seconds) for time, row count for rows
    timestamp_field: TIME_FIRST
    consensus: majority   # majority or threshold
    threshold: 0.5        # used by consensus: threshold
```

Time-windowed CSV input must be sorted by `timestamp_field`; window bounds are
`[start, end)`. For fixed row windows, use `type: rows` and a positive integer `size`.

Processing of the windows:

1. **Flow-based modules** (flow annotators and detectors) run in every window.
2. **Multi-devices are not processed again**: once an IP is flagged as a multi-device
   in a window (e.g. NAT, more MAC addresses), it is skipped in all later windows. Its
   final result keeps the flag, the index of the window and the evidence.
3. **Window voting**: for every flow-based annotator, its annotations from all windows
   are combined into one annotation. Voting is hierarchical (group → class,
   os_family → os_type → os_version) and missing values abstain:
   - `majority`: a value needs more than 1/2 of the votes,
   - `threshold`: a value needs at least `threshold` (0 < threshold ≤ 1) of the votes.

   Ties abstain. If the windows of one annotator describe incompatible operating
   systems, the IP is flagged as a multi-device.
4. **IP-based modules** run only once for every IP, after all windows.
5. The final annotation is merged from the voted flow-based annotations and the
   IP-based annotations, as in the processing without windows.

When `data_export` is enabled, `_ip_data.json` includes the voted annotations, the
voting summary (`data["window_voting"]`) and the compact result of each window
(`window_results`). Time-windowed reannotation processes only previously unseen IP and
window combinations, keeps saved multi-device IPs skipped and runs IP-based modules only
for unseen IPs. Row-window reannotation is not supported because row positions are not
stable.

## Annotators

Currently implemented:

- `sni_annotator`
- `shodan_annotator`
- `useragent_annotator`
- `mac_annotator`
- `hostname_annotator`
- `hand_annotator`
- `nat_detector` (TTL and source port heuristic)

### Adding a New Module

A module is a file named `<name>_annotator.py` or `<name>_detector.py` placed in its own
folder in `annotators_path` (in `ip/` or `flow/` by its kind) or `detectors_path`. The file defines a class derived from
`IPAnnotator`, `FlowAnnotator` or `Detector` whose `name` matches the configuration
section:

```python
from annotation import Annotation
from config import Requirement
from core import FlowAnnotator


class ExampleAnnotator(FlowAnnotator):
    """Annotate IPs that use the TTL 128 as Windows devices."""

    name = "example_annotator"          # configuration section and annotation key
    description = "example annotation"  # label of progress logs
    REQUIREMENTS = (Requirement("field", str),)  # keys of the module section
    DAF_REQUIREMENTS = ()                        # keys of the daf section it reads

    def setup(self) -> None:
        """Load databases, called once before the first run."""

    def required_columns(self) -> tuple:
        """Return the dataset columns checked before the run."""

        return (self.config["field"],)

    def annotate_ip(self, ip, flows) -> None:
        """Annotate one IP by its flows."""

        if (flows[self.config["field"]] == 128).all():
            ip.add_annotation(self.name, Annotation(None, None, "windows", "windows", None))
```

An IP-based annotator implements `annotate_ip(self, ip)` instead, a detector implements
`detect(self, ip, flows)` returning a dictionary with the boolean key `detected`.
Enable the module in the config:

```yaml
example_annotator:
    enabled: True
    path: auto
    field: "TTL"
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


## Tests

Unit tests use `pytest` and run from the repository root. They are organized by the
tested part: `tests/daf` (framework), `tests/annotators` and `tests/detectors`.

```sh
pip install pytest
python -m pytest
```

## License

BSD-3-Clause  
(C) 2025 CESNET, z.s.p.o.
