#!/usr/bin/python3
"""
Author(s): Filip Chodura <chodufil@cvut.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: loader.py
Description: Discovery, import and initialization of DAF annotator and detector modules.
"""

import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from types import ModuleType
from typing import List, Optional, Tuple

from config import Configurable, Requirement
from core import DAFModule

logger = logging.getLogger("Load")


class ModuleLoader(Configurable):
    """Find, import and initialize the modules enabled in the configuration.

    Module files named ``*annotator.py`` or ``*detector.py`` are searched for in the
    subdirectories of ``daf.annotators_path`` and ``daf.detectors_path``. Modules whose
    ``path`` is not ``auto`` are loaded from the configured path. Every module file must
    define a :class:`core.DAFModule` subclass whose ``name`` matches its section.

    Attributes
    ----------
    config : dict
        Complete DAF configuration.
    """

    REQUIREMENTS = (
        Requirement("annotators_path", str, path="dir"),
        Requirement("detectors_path", str, path="dir"),
    )
    MODULE_REQUIREMENTS = (
        Requirement("enabled", bool),
        Requirement("path", str, default="auto"),
    )

    def __init__(self, config: dict) -> None:
        """Initialize the loader and check the configuration of module discovery.

        Parameters
        ----------
        config : dict
            Complete DAF configuration.

        Raises
        ------
        config.ConfigError
            If a module directory or the ``enabled`` flag of a module is invalid.
        """

        self.config = config
        self.check_config(config["daf"], "daf")
        for name, section in config.items():
            if name != "daf":
                self.check_config(section, name, "MODULE_REQUIREMENTS")

    @staticmethod
    def import_file(path: Path) -> ModuleType:
        """Import a module file and register it in ``sys.modules``.

        The module name is derived from the path relative to the working directory, e.g.
        ``./annotators/sni_annotator/sni_annotator.py`` is imported as
        ``annotators.sni_annotator.sni_annotator``. Registering the module allows relative
        imports inside module packages and unpickling of objects defined in the module.

        Parameters
        ----------
        path : pathlib.Path
            Path to the Python file.

        Returns
        -------
        types.ModuleType
            Imported module.
        """

        module_name = ".".join(path.with_suffix("").parts)
        if module_name in sys.modules:
            return sys.modules[module_name]

        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            del sys.modules[module_name]
            raise
        return module

    @staticmethod
    def find_class(module: ModuleType, name: str) -> Optional[type]:
        """Find the :class:`core.DAFModule` subclass implementing module ``name``.

        Parameters
        ----------
        module : types.ModuleType
            Imported module file.
        name : str
            Name of the configuration section, which must match the class attribute ``name``.

        Returns
        -------
        type or None
            The module class, or None if the file does not define one.
        """

        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, DAFModule)
                and not inspect.isabstract(obj)
                and obj.__module__ == module.__name__
                and obj.name == name
            ):
                return obj
        return None

    def create(self, name: str, path: Path) -> DAFModule:
        """Import a module file and create the module instance.

        Parameters
        ----------
        name : str
            Name of the configuration section of the module.
        path : pathlib.Path
            Path to the module file.

        Returns
        -------
        DAFModule
            Initialized module.

        Raises
        ------
        ValueError
            If the file does not define the module class.
        """

        module_class = self.find_class(self.import_file(path), name)
        if module_class is None:
            logger.error(f"DAF:: Module file {path} does not define module {name}")
            raise ValueError(f"DAF:: Module file {path} does not define module {name}")
        return module_class(self.config)

    def discover(self) -> List[Tuple[str, Path]]:
        """Find the files of the enabled modules.

        Returns
        -------
        list
            ``(name, path)`` of every enabled module that was found.
        """

        found = []
        discovered = set()
        for directory in (self.config["daf"]["annotators_path"], self.config["daf"]["detectors_path"]):
            for folder in sorted(Path(directory).iterdir()):
                if not folder.is_dir():
                    continue
                for file in sorted(folder.iterdir()):
                    if not (file.name.endswith("annotator.py") or file.name.endswith("detector.py")):
                        continue
                    name = file.name.split(".")[0]
                    if name not in self.config:
                        logger.warning(
                            f"DAF:: Found annotator={name}, but configuration is missing in config file, skipping."
                        )
                        continue
                    discovered.add(name)
                    if self.config[name]["enabled"] is True:
                        found.append((name, file))

        # Modules not found in the module directories are loaded from their path
        for name, section in self.config.items():
            if name == "daf" or name in discovered or section["enabled"] is False:
                continue
            if section["path"] == "auto":
                logger.warning(
                    f"DAF:: Unable to locate annotator={name}. Please write path to the config file or place annotator into the 'annotators_path'"
                )
                continue
            if not Path(section["path"]).is_file():
                logger.warning(f"DAF:: Unable to locate annotator={name} at path={section['path']}")
                continue
            found.append((name, Path(section["path"])))
        return found

    def load(self) -> List[DAFModule]:
        """Load and initialize all enabled modules.

        Returns
        -------
        list
            Initialized :class:`core.DAFModule` instances.
        """

        return [self.create(name, path) for name, path in self.discover()]


__all__ = ["ModuleLoader"]
