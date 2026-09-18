# Nmap Annotator

**Module:** `NmapAnnotator` in `nmap_annotator.py`, an IP-based annotator (`IPAnnotator`) and an IP source (`IPSource`). It runs once per IP, also in windowed processing.

The Nmap annotator maps the evidence of an Nmap XML report to DAF's device and
operating-system taxonomies. It works in one of two modes:

- **passive** (default): DAF imports a completed report (`xml_file`) and adds the
  IPs of the report to the annotated IPs.
- **active**: DAF runs Nmap itself on the annotated IPs and the configured `targets`,
  see [Active mode](#active-mode).

## What Nmap contributes

| Scan evidence | DAF use | Limitation |
|---|---|---|
| Host discovery | Adds explicitly listed up or down IPs | A filtered host can look down |
| Port state | Preserved as evidence | A port number alone is not an application |
| `-sV` service detection | Service role, product, device and OS CPE evidence | A service can be containerized or forwarded |
| `-O` OS detection | OS family and device fingerprint evidence | Linux fingerprints often cannot name a distribution |

OS fingerprinting is most effective when Nmap can observe at least one open and one
closed TCP port. Service CPEs (structured product identifiers) can complement it—for
example, by identifying Ubuntu when `-O` only identifies Linux. DAF keeps uncertainty:
conflicting eligible observations abstain for the affected fields, application versions
remain evidence, and kernel versions are not treated as distribution releases.

The Nmap-to-DAF “topology” in this feature is the taxonomy mapping above. Nmap
traceroute paths do not create DAF IP objects.

## Configuration

```yaml
nmap_annotator:
  enabled: true
  path: auto
  xml_file: "../examples/nmap/nmap_scan_example.xml"
  db_file: "../dbs/nmap_annotator-rules.csv"
  min_os_accuracy: 95
  min_service_confidence: 7
```

`min_os_accuracy` uses Nmap's 0–100 OS-match scale. `min_service_confidence`
uses its 0–10 service-identification scale. Only open services identified by active
probing (`method="probed"`) are eligible for annotation. Service confidence describes
the service identification, not the probability that the host runs a distribution.
Paths are resolved relative to DAF's working directory, like other DAF configuration
paths.

The complete parsed evidence is saved under `IP.data["nmap_annotator"]`. The
annotator contributes at most one normal DAF annotation per host. A report can be the
only input, or its IPs can be combined with a flow dataset.

For a standalone Nmap run, set `daf.min_annotators_count: 1`; a single Nmap annotation
cannot meet a two-annotator consensus threshold. The ordinary example configuration
keeps its existing threshold of 2.

## Active mode

In the active mode DAF starts Nmap, saves its XML report and annotates the IPs from it:

```yaml
nmap_annotator:
  enabled: true
  path: auto
  mode: active
  nmap_path: nmap                  # Nmap executable
  arguments: ["-sS", "-sV", "-O", "-n", "-T3", "--top-ports", "1000"]
  targets: ["192.168.10.0/24"]     # additional IPs or networks to scan
  scan_dataset_ips: true           # scan the IPs selected from the dataset
  output_xml: "../examples/nmap/active_scan.xml"
  timeout: 3600                    # seconds, unlimited if not set
  privileged: false                # pass --privileged for Nmap with capabilities
  dry_run: false                   # only log the Nmap command
  db_file: "../dbs/nmap_annotator-rules.csv"
  min_os_accuracy: 95
  min_service_confidence: 7
```

- **Targets** are the annotated IPs (dataset IPs filtered by `daf.ip_ranges`) if
  `scan_dataset_ips` is true, plus all addresses of the configured `targets`. Configured
  targets are added to the annotated IPs, so DAF can run without a dataset.
- **Multi-devices are not scanned.** The active annotator runs after the other modules
  (it is *deferred*), so IPs already flagged as multi-devices (e.g. by the NAT detector)
  are skipped. In windowed processing it runs once after all windows.
- **One scan** covers all targets. Targets are passed to Nmap in a temporary file
  (`-iL`), the report is written by `-oX` and Nmap is started without a shell.
  `arguments` must not contain `-iL`, `-oX` or `-oA`.
- **Privileges**: `-sS`, `-sU`, `-O`, `-A` and other raw-socket options require root.
  Without root DAF fails before scanning; run DAF as root, set `privileged: true` for
  Nmap with capabilities, or use unprivileged options such as `-sT -sV`.
- `dry_run: true` logs the Nmap command without scanning; no Nmap annotation is created.

Only scan networks you are authorized to scan.

## Rule database

The CSV columns are:

| Column | Meaning |
|---|---|
| `source` | Nmap evidence field to examine |
| `pattern` | Case-insensitive Python regular expression |
| `group`, `class` | DAF device taxonomy output |
| `os_family`, `os_type`, `os_version` | DAF OS taxonomy output |

Supported sources are `os_match_name`, `os_class_family`, `os_class_type`,
`os_class_cpe`, `service_name`, `service_product`, `service_version`,
`service_extra_info`, `service_os_type`, `service_device_type`, and `service_cpe`.
Output labels are validated against the configured DAF taxonomies. Regex capture
references such as `\1` may be used in `os_version`.

For example, a local product alias can be added as:

```csv
service_product,^Acme Secure Gateway$,net-device,firewall,,,
```

With customized DAF taxonomies, copy the shipped database and change or remove every
output label that is not present in the custom taxonomy, then point `db_file` at that
copy. DAF rejects an invalid source, regex, or taxonomy label when the module starts.

Generic evidence deliberately produces partial labels. For example, a generic Linux
fingerprint sets only `os_family=linux`; it does not imply Ubuntu. Likewise, Nmap's
generic `router` type sets `group=net-device` without claiming it is a core router.
