#!/usr/bin/python3
"""
Author(s): Filip Chodura <chodufil@cvut.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: pipeline.py
Description: Annotation pipeline of DAF: runs modules, finalizes annotations and exports results.
"""

import argparse
import logging
import traceback
from threading import Thread
from typing import Optional

from config import Configurable, Requirement
from dataset import FlowDataset
from ip import IPCollection, IPDataFile
from ip_ranges import IPSelector
from output import AnnotationListExporter, DatasetAnnotator, OutputPaths
from stats import AnnotationStatistics

logger = logging.getLogger("DAF")


class ModuleRunner:
    """Run annotator and detector modules, either in parallel threads or sequentially.

    Attributes
    ----------
    modules : list
        Initialized :class:`core.DAFModule` instances.
    threads : bool
        If True, every module runs in its own thread.
    """

    def __init__(self, modules: list, threads: bool) -> None:
        """Initialize the runner.

        Parameters
        ----------
        modules : list
            Initialized :class:`core.DAFModule` instances.
        threads : bool
            Run modules in parallel threads.
        """

        self.modules = modules
        self.threads = threads

    def modules_of_kind(self, kind: str) -> list:
        """Return modules of one kind.

        Parameters
        ----------
        kind : str
            ``"ip"`` for IP-based or ``"flow"`` for flow-based modules.

        Returns
        -------
        list
            Matching modules.
        """

        return [module for module in self.modules if module.kind == kind]

    def run(self, ip_addresses: list, flows_by_ip: dict, kind: Optional[str] = None) -> None:
        """Run modules on the given IP addresses.

        IP-based modules annotate every IP address. Flow-based modules annotate IP
        addresses present in ``flows_by_ip``, see :meth:`core.FlowAnnotator.select_targets`.

        Parameters
        ----------
        ip_addresses : list
            IP objects to annotate.
        flows_by_ip : dict
            Flow DataFrames keyed by source IP address string.
        kind : str, optional
            Run only modules of this kind (``"ip"`` or ``"flow"``). All modules by default.

        Raises
        ------
        RuntimeError
            If any of the modules failed.
        """

        errors = []

        def start(module) -> None:
            """Run one module and collect its exception."""

            try:
                module.run(ip_addresses, flows_by_ip)
                logger.info(f"    -- {module.name} finished.")
            except Exception:  # pylint: disable=broad-except
                errors.append([module.name, traceback.format_exc()])

        modules = self.modules if kind is None else self.modules_of_kind(kind)
        if not modules:
            return

        logger.info("  -- Starting annotators:")
        threads = []
        for module in modules:
            if self.threads:
                logger.info(f"    -- {module.name} started ... ")
                thread = Thread(target=start, args=(module,))
                threads.append(thread)
                thread.start()
            else:
                logger.info(f"    -- {module.name} started (sequential)... ")
                start(module)

        for thread in threads:
            thread.join()

        if errors:
            for name, message in errors:
                logger.error(f"Module: {name}\n{message}")
            logger.error("Some modules failed.")
            logger.error("Exiting annotation process.")
            raise RuntimeError("Some modules failed. Exiting annotation process.")

        logger.info("  -- all annotators finished")


class DAFRunner(Configurable):
    """Annotation process of one DAF execution.

    Attributes
    ----------
    arg : argparse.Namespace
        Command-line arguments.
    config : dict
        DAF configuration.
    modules : list
        Initialized annotator and detector modules.
    module_runner : ModuleRunner
        Runner executing the modules.
    selector : IPSelector
        Selection of the dataset IPs.
    paths : OutputPaths
        Names of the output files.
    exporter : AnnotationListExporter
        Writer of the IP annotation list.
    statistics : AnnotationStatistics
        Summary of the annotation.
    """

    REQUIREMENTS = (
        Requirement("min_annotation_count", int, minimum=0),
        Requirement("min_annotators_count", int, minimum=0),
        Requirement("threads", bool),
        Requirement("data_export", bool),
    )

    def __init__(self, arg: argparse.Namespace, config: dict, modules: list) -> None:
        """Check the configuration and initialize the process.

        Parameters
        ----------
        arg : argparse.Namespace
            Command-line arguments.
        config : dict
            DAF configuration.
        modules : list
            Initialized annotator and detector modules.
        """

        self.arg = arg
        self.config = config
        self.daf_config = self.check_config(config["daf"], "daf")
        self.modules = modules
        self.module_runner = ModuleRunner(modules, self.daf_config["threads"])
        self.selector = IPSelector(config)
        self.paths = OutputPaths(arg)
        self.exporter = AnnotationListExporter(config, arg.d)
        self.statistics = AnnotationStatistics(config)

    @property
    def src_ip_field(self) -> str:
        """Return the name of the source IP column."""

        return self.daf_config["src_ip_field"]

    def run(self) -> None:
        """Start the annotation or the reannotation, depending on the arguments."""

        if self.arg.reannotation is None:
            self.process_dataset()
        else:
            self.process_reannotation()

    def load_dataset(self) -> FlowDataset:
        """Load the complete dataset to memory.

        Returns
        -------
        FlowDataset
            Loaded flows.
        """

        return FlowDataset.read_csv(self.arg.dataset, self.arg.d, self.src_ip_field)

    def finalize(self, ip_addresses: list) -> None:
        """Merge module annotations into the final annotation of each IP.

        Parameters
        ----------
        ip_addresses : list
            Annotated IP objects.
        """

        logger.info("  -- finalize annotation of IPs ... ")
        logger.info(f"    -- minimum annotators count: {self.daf_config['min_annotators_count']}")
        logger.info(f"    -- minimum annotation count: {self.daf_config['min_annotation_count']}")
        for ip in ip_addresses:
            ip.perform_annotation(self.daf_config["min_annotators_count"])
        logger.info("  -- finalize annotation of IPs ... DONE")

    def annotate(self, ip_addresses: list, flows_by_ip: dict) -> None:
        """Run all modules and finalize the annotation of the given IPs.

        Parameters
        ----------
        ip_addresses : list
            IP objects to annotate.
        flows_by_ip : dict
            Flow DataFrames keyed by source IP address string.
        """

        self.module_runner.run(ip_addresses, flows_by_ip)
        self.finalize(ip_addresses)

    def export_ip_data(self, ip_addresses: list) -> None:
        """Save the complete IP state as JSON.

        Parameters
        ----------
        ip_addresses : list
            Annotated IP objects.
        """

        IPDataFile(self.paths.ip_data).save(ip_addresses)

    def process_dataset(self) -> None:
        """Annotate the whole dataset in memory and export the results."""

        logger.info("Process annotation in memory:")
        dataset = self.load_dataset()

        logger.info("  -- getting IP addresses for annotation from dataset ... ")
        ip_addresses = self.selector.select(dataset.flows)
        self.annotate(ip_addresses, dataset.flows_by_ip())

        self.exporter.write(ip_addresses, self.paths.annotation_list)
        flows = DatasetAnnotator(ip_addresses, self.src_ip_field).write(
            dataset.flows, self.paths.annotated_dataset
        )
        if self.daf_config["data_export"]:
            self.export_ip_data(ip_addresses)
        self.statistics.log(ip_addresses, flows)

    def process_reannotation(self) -> None:
        """Reuse saved IP state and annotate only IPs not present in it.

        If a dataset is given, its IPs are compared with the saved state and modules are
        started only for unseen IPs. Saved IPs keep their evidence and annotations.
        """

        logger.info("Process reannotation:")
        logger.info(f"  -- loading raw annotation information from {self.arg.reannotation} ... ")
        ip_addresses = IPCollection(IPDataFile(self.arg.reannotation).load())

        dataset = None
        new_ips = []
        if self.arg.dataset is not None:
            dataset = self.load_dataset()
            logger.info("  -- getting IP addresses for annotation from dataset ... ")
            new_ips = [ip for ip in self.selector.select(dataset.flows) if ip not in ip_addresses]

        if new_ips:
            logger.info("  -- starting additional annotation processes for unseen IPs ... ")
            new_keys = {str(ip.ip_addr) for ip in new_ips}
            self.module_runner.run(new_ips, dataset.flows_by_ip(new_keys))

        ip_addresses = ip_addresses.to_list() + new_ips
        self.finalize(ip_addresses)

        self.exporter.write(ip_addresses, self.paths.annotation_list)
        flows = None
        if dataset is not None:
            flows = DatasetAnnotator(ip_addresses, self.src_ip_field).write(
                dataset.flows, self.paths.annotated_dataset
            )

        if self.daf_config["data_export"] and new_ips:
            self.export_ip_data(ip_addresses)
            self.statistics.log(ip_addresses, flows)
        else:
            self.statistics.log(ip_addresses, None)


__all__ = ["DAFRunner", "ModuleRunner", "RunnerFactory"]
