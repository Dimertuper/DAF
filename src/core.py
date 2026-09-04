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
       :meth:`before_run` and then :meth:`annotate_ip` for each IP.

    Attributes
    ----------
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

    def run(self, ip_addresses: list, flows_by_ip: Optional[dict] = None) -> None:
        """Annotate a batch of IP addresses.

        Calls :meth:`setup` on first use, then :meth:`before_run`, and finally
        :meth:`annotate_ip` for each IP address while logging the progress.

        Parameters
        ----------
        ip_addresses : list
            IP objects to annotate. They are modified in place.
        flows_by_ip : dict, optional
            Flow DataFrames keyed by source IP address string.
        """

        flows_by_ip = flows_by_ip or {}
        self.ensure_setup()
        self.before_run(ip_addresses, flows_by_ip)

        total_ips = len(ip_addresses)
        log_interval = max(1, total_ips // 10)
        for cnt_ip, ip in enumerate(ip_addresses, start=1):
            if self.daf_config.get("progress_print") and (
                cnt_ip % log_interval == 0 or cnt_ip == total_ips
            ):
                progress = (cnt_ip / total_ips) * 100
                self.logger.info(f"    -- {self.label} ... {progress:.0f} %")

            self.annotate_ip(ip, flows_by_ip.get(str(ip.ip_addr)))

        self.logger.info(f"    -- {self.label} ... DONE")

    @abstractmethod
    def annotate_ip(self, ip: IP, flows: Optional[pd.DataFrame]) -> None:
        """Annotate one IP address.

        Parameters
        ----------
        ip : IP
            IP object to annotate in place.
        flows : pd.DataFrame or None
            Flows whose source is ``ip``, or None if the IP has no source flows.
        """


__all__ = ["DAFModule"]
