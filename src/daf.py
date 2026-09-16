#!/usr/bin/python3
"""
Author(s): Matej Hulák <hulak@cesnet.cz>

Copyright: (C) 2025 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: daf.py
Description: Command-line application of the Device Annotation Framework (DAF).
"""

# Standard Libraries Imports
import argparse
import logging
import time
from argparse import RawTextHelpFormatter
from datetime import timedelta
from typing import List, Optional, Union

# Local Imports
from annotation import Annotation
from config import ConfigLoader
from core import IPSource
from loader import ModuleLoader
from pipeline import DAFRunner, WindowedDAFRunner
from taxonomy_checker import TaxonomyChecker
from windows import WindowConfig

logger = logging.getLogger("DAF")


class DAFApplication:
    """Device Annotation Framework application.

    The application is created with the parsed command-line arguments and the loaded
    configuration. It loads the taxonomies and the modules, selects the runner of the
    annotation process and runs it. Every component checks the configuration it uses
    when it is created, so configuration errors are reported before any data is read.

    Attributes
    ----------
    arg : argparse.Namespace
        Parsed command-line arguments.
    config : dict
        Loaded configuration, see :class:`config.ConfigLoader`.
    modules : list
        Annotator and detector modules.
    """

    def __init__(
        self, arg: argparse.Namespace, config: dict, modules: Optional[list] = None
    ) -> None:
        """Initialize the application.

        Parameters
        ----------
        arg : argparse.Namespace
            Parsed command-line arguments, see :meth:`parse_arguments`.
        config : dict
            Loaded configuration.
        modules : list, optional
            Already initialized modules. If not given, they are loaded by :meth:`load`.
        """

        self.arg = arg
        self.config = config
        self.modules = modules

    @staticmethod
    def parse_logfile(value: str) -> Union[bool, str]:
        """Convert the ``--logfile`` argument.

        Parameters
        ----------
        value : str
            ``True`` (console), ``False`` (disabled) or a path of the log file.

        Returns
        -------
        bool or str
            True, False or the path.
        """

        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0", "none"):
            return False
        return value

    @staticmethod
    def setup_logging(logfile) -> None:
        """
        Set up logging configuration based on logfile parameter.

        Parameters
        ----------
        logfile : bool or str
            Determines the logging configuration:
            - If `True`, logs are printed to the console.
            - If a `str`, logs are written to the specified file.
            - If `False`, logging is disabled.

        Logging is configured again on every call (``force``), so a later call
        replaces the handlers of a previous one.
        """

        logging.disable(logging.NOTSET)
        if logfile is True:
            logging.basicConfig(
                force=True,
                level=logging.DEBUG,
                format="{asctime} - {levelname} - {name} : {message}",
                style="{",
                datefmt="%d-%m-%Y %H:%M",
            )
        elif isinstance(logfile, str):
            logging.basicConfig(
                force=True,
                filename=logfile,
                filemode="a",
                level=logging.DEBUG,
                format="{asctime} - {levelname} - {name} : {message}",
                style="{",
                datefmt="%d-%m-%Y %H:%M",
            )
        else:
            logging.disable(logging.CRITICAL)

    @staticmethod
    def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
        """
        Parse command-line arguments.

        Parameters
        ----------
        argv : list, optional
            Command-line arguments, ``sys.argv`` by default.

        Returns
        -------
        argparse.Namespace
            Parsed command-line arguments.
        """

        parser = argparse.ArgumentParser(
            description="""

        Usage:""",
            formatter_class=RawTextHelpFormatter,
        )

        parser.add_argument(
            "--config",
            help="Define path to DAFs configuration file. Default: './daf_config.yml'",
            type=str,
            default="daf_config.yml",
            required=True,
        )

        parser.add_argument(
            "--dataset",
            help="Dataset CSV file for annotation.",
            type=str,
            metavar="FILE.csv",
            default=None,
        )

        parser.add_argument(
            "--logfile",
            help="Define logging output. If True, logs are printed to console. If file, logs are saved to file. If False, logging is disabled. Default: True",
            type=DAFApplication.parse_logfile,
            default=True,
        )

        parser.add_argument(
            "-d",
            help="Delimiter of input dataset. Default: ','",
            type=str,
            metavar="CHAR",
            default=",",
        )

        parser.add_argument(
            "--reannotation",
            help="Filling the raw annotation information file into this parameter process to reannotate dataset. Default: disabled",
            type=str,
            default=None,
        )

        return parser.parse_args(argv)

    def load(self) -> None:
        """Load the taxonomies and the modules.

        Raises
        ------
        ValueError
            If there is neither a dataset, a reannotation file nor an IP source module.
        """

        Annotation.set_taxonomy_checker(TaxonomyChecker.from_config(self.config))

        if self.modules is None:
            logger.info("Loading annotators ... ")
            self.modules = ModuleLoader(self.config).load()
        logger.info("Loaded annotators:")
        for module in self.modules:
            logger.info(f"\t{module.name} ({type(module).__name__})")
        if (
            self.arg.dataset is None
            and self.arg.reannotation is None
            and not any(isinstance(module, IPSource) for module in self.modules)
        ):
            raise ValueError("No dataset, reannotation file, or module input specified. Exiting.")

    def create_runner(self) -> DAFRunner:
        """Create the runner of the configured annotation process.

        Returns
        -------
        DAFRunner
            :class:`pipeline.WindowedDAFRunner` if windowing is enabled and a dataset
            is given, otherwise :class:`pipeline.DAFRunner`.
        """

        if WindowConfig.is_enabled(self.config):
            if self.arg.dataset is not None:
                return WindowedDAFRunner(self.arg, self.config, self.modules)
            logger.info("No dataset given, windowing is not used.")
        return DAFRunner(self.arg, self.config, self.modules)

    def run(self) -> None:
        """Load the taxonomies and modules and run the annotation process."""

        if self.arg.dataset is not None:
            logger.info(f"Working with dataset: {self.arg.dataset}")
        if self.arg.reannotation is not None:
            logger.info(f"Working with reannotation file: {self.arg.reannotation}")
        if self.arg.dataset is not None and self.arg.reannotation is not None:
            logger.info(
                "Both dataset and reannotation file specified. Reannotation will be performed on the dataset."
            )

        self.load()
        runner = self.create_runner()

        start = time.time()
        runner.run()
        elapsed = time.time() - start
        logger.info(f"Annotation finished in time: {timedelta(seconds=elapsed)}\n\n")


def main(argv: Optional[List[str]] = None) -> None:
    """Run the Device Annotation Framework (DAF) from the command line.

    Parses the arguments, sets up logging, loads the configuration and runs a
    :class:`DAFApplication` with it. Errors are logged before they are raised, so they
    are also recorded in the log file.

    Parameters
    ----------
    argv : list, optional
        Command-line arguments, ``sys.argv`` by default.
    """

    arg = DAFApplication.parse_arguments(argv)
    DAFApplication.setup_logging(arg.logfile)
    logger.info("\n" * 2 + "=" * 50 + " Device Annotation Framework (DAF) " + "=" * 50 + "\n")
    try:
        logger.info(f"Loading configuration from {arg.config} ... ")
        config = ConfigLoader(arg.config).load(progress_print=arg.logfile is True)
        DAFApplication(arg, config).run()
    except Exception:
        logger.exception("DAF failed")
        raise
    finally:
        logging.shutdown()


if __name__ == "__main__":
    main()
