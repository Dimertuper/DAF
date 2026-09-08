#!/usr/bin/python3
"""
Author(s): Filip Chodura <chodufil@cvut.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: core.py
Description: Base classes of DAF annotator and detector modules.
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional

import pandas as pd

from config import ConfigError, Configurable
from ip import IP


class DAFModule(Configurable, ABC):
    """Base class of every DAF annotator and detector.

    Modules are not derived from this class directly but from one of its two kinds:

    - :class:`IPAnnotator` needs only the IP address (e.g. reverse DNS, Shodan, hand
      annotations). In windowed processing it runs only once for every IP address.
    - :class:`FlowAnnotator` derives the annotation from the flows of the IP address
      (e.g. SNI, useragent, MAC). In windowed processing it runs in every window.
      :class:`Detector` is a flow annotator detecting multi-device IPs, e.g. NAT.

    A module is configured by its own section of the DAF configuration file. The section
    name is stored in the class attribute ``name`` and is also used as the key under which
    the module stores its annotations and data in :class:`ip.IP` objects.

    The configuration a module needs is declared, not checked by hand:

    - ``REQUIREMENTS``: :class:`config.Requirement` of keys of the module section,
    - ``DAF_REQUIREMENTS``: requirements of keys of the ``daf`` section the module reads.

    Both are checked when the module is created, defaults are set into the sections.

    The life cycle of a module is:

    1. ``__init__`` checks the configuration.
    2. :meth:`setup` is called once, before the first :meth:`run`, to load databases.
    3. :meth:`run` is called for every batch of IP addresses. It calls
       :meth:`before_run` and then annotates every target IP, see :meth:`select_targets`.

    Attributes
    ----------
    kind : str
        ``"ip"`` for IP-based and ``"flow"`` for flow-based modules.
    name : str
        Name of the configuration section and the annotation key of the module.
    description : str
        Human readable label used in progress logs.
    config : dict
        Checked module configuration section.
    daf_config : dict
        Checked configuration section of the DAF framework (``config["daf"]``).
    full_config : dict
        Complete DAF configuration.
    logger : logging.Logger
        Logger of the module.
    """

    kind: str = ""
    name: str = ""
    description: str = ""
    DAF_REQUIREMENTS: tuple = ()

    def __init__(self, config: dict) -> None:
        """Initialize the module from the DAF configuration.

        Parameters
        ----------
        config : dict
            Complete DAF configuration. The module reads its own section ``config[name]``
            and the framework section ``config["daf"]``.

        Raises
        ------
        TypeError
            If the subclass does not define ``name``.
        ConfigError
            If a configuration requirement is not met.
        """

        if not self.name:
            raise TypeError(f"{type(self).__name__} must define the class attribute 'name'")

        self.logger = logging.getLogger(self.label)
        if self.name not in config:
            self.logger.error(f"Configuration section '{self.name}' not found")
            raise ConfigError(f"{self.name}: configuration section not found")

        self.full_config = config
        self.config = self.check_config(config[self.name], self.name)
        self.daf_config = self.check_config(config["daf"], "daf", "DAF_REQUIREMENTS")
        self._is_set_up = False

    @property
    def label(self) -> str:
        """Return the label used in log messages.

        Returns
        -------
        str
            ``description`` if defined, otherwise ``name``.
        """

        return self.description or self.name

    def setup(self) -> None:
        """Load databases and other resources needed by the module.

        Called once, before the first call of :meth:`run`. The default implementation
        does nothing.
        """

    def ensure_setup(self) -> None:
        """Call :meth:`setup` if it was not called yet."""

        if not self._is_set_up:
            self.setup()
            self._is_set_up = True

    def before_run(self, ip_addresses: list, flows_by_ip: dict) -> None:
        """Prepare one run, e.g. validate flow columns or precompute lookups.

        Parameters
        ----------
        ip_addresses : list
            IP objects that will be annotated in this run.
        flows_by_ip : dict
            Flow DataFrames keyed by source IP address string.
        """

    def select_targets(self, ip_addresses: list, flows_by_ip: dict) -> list:
        """Select the IP addresses the module annotates in a run.

        Parameters
        ----------
        ip_addresses : list
            IP objects passed to :meth:`run`.
        flows_by_ip : dict
            Flow DataFrames keyed by source IP address string.

        Returns
        -------
        list
            IP objects to annotate. All of them by default.
        """

        return ip_addresses

    def run(self, ip_addresses: list, flows_by_ip: Optional[dict] = None) -> None:
        """Annotate a batch of IP addresses.

        Calls :meth:`setup` on first use, then :meth:`before_run`, and finally
        :meth:`annotate` for each IP selected by :meth:`select_targets` while logging
        the progress.

        Parameters
        ----------
        ip_addresses : list
            IP objects to annotate. They are modified in place.
        flows_by_ip : dict, optional
            Flow DataFrames keyed by source IP address string.
        """

        flows_by_ip = flows_by_ip or {}
        self.ensure_setup()

        targets = self.select_targets(ip_addresses, flows_by_ip)
        if not targets:
            self.logger.info(f"    -- {self.label} ... skipped (no applicable IPs)")
            return
        self.before_run(targets, flows_by_ip)

        total_ips = len(targets)
        log_interval = max(1, total_ips // 10)
        for cnt_ip, ip in enumerate(targets, start=1):
            if self.daf_config.get("progress_print") and (
                cnt_ip % log_interval == 0 or cnt_ip == total_ips
            ):
                progress = (cnt_ip / total_ips) * 100
                self.logger.info(f"    -- {self.label} ... {progress:.0f} %")

            self.annotate(ip, flows_by_ip.get(str(ip.ip_addr)))

        self.logger.info(f"    -- {self.label} ... DONE")

    @abstractmethod
    def annotate(self, ip: IP, flows: Optional[pd.DataFrame]) -> None:
        """Dispatch one IP address to the kind specific annotation method.

        Parameters
        ----------
        ip : IP
            IP object to annotate in place.
        flows : pd.DataFrame or None
            Flows whose source is ``ip``, or None if the IP has no source flows.
        """


class IPAnnotator(DAFModule):
    """Base class of annotators that need only the IP address.

    IP annotators receive every selected IP address, including addresses without
    source flows. In windowed processing they run only once for each IP address.
    """

    kind = "ip"

    def annotate(self, ip: IP, flows: Optional[pd.DataFrame] = None) -> None:
        """Annotate one IP address, flows are ignored.

        Parameters
        ----------
        ip : IP
            IP object to annotate in place.
        flows : pd.DataFrame, optional
            Not used.
        """

        self.annotate_ip(ip)

    @abstractmethod
    def annotate_ip(self, ip: IP) -> None:
        """Annotate one IP address.

        Parameters
        ----------
        ip : IP
            IP object to annotate in place.
        """


class FlowAnnotator(DAFModule):
    """Base class of annotators deriving the annotation from flows of the IP address.

    Only IP addresses with source flows are annotated unless ``requires_src_flows``
    is False. In windowed processing flow annotators run in every window.

    Attributes
    ----------
    requires_src_flows : bool
        If True, IP addresses without source flows are skipped.
    """

    kind = "flow"
    requires_src_flows: bool = True

    def required_columns(self) -> tuple:
        """Return the flow columns the module needs.

        Returns
        -------
        tuple
            Column names, empty by default.
        """

        return ()

    def validate_flows(self, flows: pd.DataFrame) -> None:
        """Check that the flows contain all :meth:`required_columns`.

        Parameters
        ----------
        flows : pd.DataFrame
            Flows of one IP address, used as a sample of the dataset schema.

        Raises
        ------
        KeyError
            If a required column is missing.
        """

        missing = [column for column in self.required_columns() if column not in flows.columns]
        if missing:
            self.logger.error(f"Columns not found in the dataset: {', '.join(missing)}")
            raise KeyError(f"{self.name}:: columns not found in the dataset: {', '.join(missing)}")

    def select_targets(self, ip_addresses: list, flows_by_ip: dict) -> list:
        """Select IP addresses with source flows, or all if they are not required.

        Parameters
        ----------
        ip_addresses : list
            IP objects passed to :meth:`run`.
        flows_by_ip : dict
            Flow DataFrames keyed by source IP address string.

        Returns
        -------
        list
            IP objects to annotate.
        """

        if not self.requires_src_flows:
            return ip_addresses
        return [ip for ip in ip_addresses if str(ip.ip_addr) in flows_by_ip]

    def before_run(self, ip_addresses: list, flows_by_ip: dict) -> None:
        """Validate the dataset schema on the first non-empty flow table.

        Parameters
        ----------
        ip_addresses : list
            IP objects that will be annotated.
        flows_by_ip : dict
            Flow DataFrames keyed by source IP address string.
        """

        sample = next((flows for flows in flows_by_ip.values() if not flows.empty), None)
        if sample is not None:
            self.validate_flows(sample)

    def annotate(self, ip: IP, flows: Optional[pd.DataFrame]) -> None:
        """Annotate one IP address by its flows.

        Parameters
        ----------
        ip : IP
            IP object to annotate in place.
        flows : pd.DataFrame or None
            Flows whose source is ``ip``.
        """

        self.annotate_ip(ip, flows)

    @abstractmethod
    def annotate_ip(self, ip: IP, flows: Optional[pd.DataFrame]) -> None:
        """Annotate one IP address by its flows.

        Parameters
        ----------
        ip : IP
            IP object to annotate in place.
        flows : pd.DataFrame or None
            Flows whose source is ``ip``. None only if ``requires_src_flows`` is False.
        """


class Detector(FlowAnnotator):
    """Base class of flow-based detectors of multi-device IP addresses (e.g. NAT).

    A detector does not create an annotation. It returns a detection result, which is
    stored in ``ip.data[name]``. Positive results (``result["detected"]`` is True) are
    also added to ``ip.multi_device`` under ``evidence_label``.

    Attributes
    ----------
    evidence_label : str
        Label of the evidence stored in ``ip.multi_device``.
    """

    evidence_label: str = ""

    def annotate_ip(self, ip: IP, flows: Optional[pd.DataFrame]) -> None:
        """Run the detection on one IP address and store its result.

        Parameters
        ----------
        ip : IP
            IP object to check.
        flows : pd.DataFrame or None
            Flows whose source is ``ip``.
        """

        if flows is None or flows.empty:
            return
        result = self.detect(ip, flows)
        if result is None:
            return
        ip.add_data(self.name, result)
        if result.get("detected"):
            ip.multi_device.append([self.evidence_label or self.name, result])

    @abstractmethod
    def detect(self, ip: IP, flows: pd.DataFrame) -> Optional[dict]:
        """Detect whether the IP address hides multiple devices.

        Parameters
        ----------
        ip : IP
            IP object to check.
        flows : pd.DataFrame
            Non-empty flows whose source is ``ip``.

        Returns
        -------
        dict or None
            JSON-serializable result with the boolean key ``"detected"``, or None if
            the detection could not be performed.
        """


__all__ = ["DAFModule", "Detector", "FlowAnnotator", "IPAnnotator"]
