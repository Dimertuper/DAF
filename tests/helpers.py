"""Helpers shared by the DAF unit tests."""

import importlib
from pathlib import Path

import numpy as np
import pandas as pd

from dataset import FlowDataset

from ip import IP

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
ANNOTATORS = SRC / "annotators"
DETECTORS = SRC / "detectors"


def daf_config(**sections) -> dict:
    """Return a minimal DAF configuration extended by enabled module sections."""

    config = {
        "daf": {
            "ip_ranges": "ALL",
            "src_ip_field": "SRC_IP",
            "dst_ip_field": None,
            "src_port_field": "SRC_PORT",
            "dst_port_field": "DST_PORT",
            "annotators_path": str(ANNOTATORS),
            "detectors_path": str(DETECTORS),
            "os_taxonomy_path": str(ROOT / "taxonomies" / "os_taxonomy.json"),
            "device_taxonomy_path": str(ROOT / "taxonomies" / "dev_taxonomy.json"),
            "min_annotation_count": 1,
            "min_annotators_count": 1,
            "export_full_annotation": True,
            "threads": False,
            "data_export": True,
            "progress_print": False,
        }
    }
    for name, section in sections.items():
        config[name] = {"enabled": True, "path": "auto", **section}
    return config


def flows_of(ip: str, rows: int = 1, **columns) -> pd.DataFrame:
    """Return ``rows`` flows of one source IP with the given columns."""

    data = {"SRC_IP": [ip] * rows}
    for name, value in columns.items():
        data[name] = value if isinstance(value, list) else [value] * rows
    return pd.DataFrame(data)


def ips(*addresses: str) -> list:
    """Return new IP objects."""

    return [IP(address) for address in addresses]


def module(path: Path):
    """Import a shipped module file under the name DAF uses, e.g. ``annotators.x.x``."""

    return importlib.import_module(".".join(path.relative_to(SRC).with_suffix("").parts))


def random_flows(columns: dict, rows: int = 400, ips: int = 30, seed: int = 0) -> pd.DataFrame:
    """Return random flows of ``ips`` source IPs, column values drawn from ``columns``."""

    rng = np.random.default_rng(seed)
    data = {"SRC_IP": [f"10.0.0.{index}" for index in rng.integers(1, ips + 1, rows)]}
    for name, values in columns.items():
        data[name] = [values[index] for index in rng.integers(0, len(values), rows)]
    return pd.DataFrame(data)


def per_ip_and_batch(module_factory, flows: pd.DataFrame) -> tuple:
    """Annotate the same flows IP by IP and all at once, return both exported states."""

    dataset = FlowDataset(flows, "SRC_IP")
    addresses = sorted(dataset.ip_keys())

    per_ip = ips(*addresses)
    module = module_factory()
    module.ensure_setup()
    module.before_run(per_ip, dict(dataset.groups))
    for ip in per_ip:
        module.annotate(ip, dataset.groups.get(str(ip.ip_addr)))

    batch = ips(*addresses)
    module_factory().run(batch, FlowDataset(flows, "SRC_IP"))
    return [ip.export() for ip in per_ip], [ip.export() for ip in batch]
