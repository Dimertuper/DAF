#!/usr/bin/python3
"""
Author(s): Filip Chodura <chodufil@cvut.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

File: config.py
Description: Loading of the DAF configuration and the declarative checking of its requirements.
"""

import logging
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

import yaml

logger = logging.getLogger("Config")

_MISSING = object()


class ConfigError(ValueError):
    """Raised when a configuration section does not meet the requirements of its user."""


class Requirement:
    """Requirement of one key of a configuration section.

    Classes using the configuration declare their requirements, see :class:`Configurable`.

    Attributes
    ----------
    key : str
        Configuration key.
    types : tuple
        Accepted value types, any type if empty. ``bool`` is never accepted as a number.
    required : bool
        Whether the key must be present. Keys with a default are never required.
    default : Any
        Value set when the key is missing.
    nullable : bool
        Whether None is accepted.
    choices : tuple, optional
        Accepted values.
    minimum, maximum : float, optional
        Inclusive bounds of numeric values.
    path : str, optional
        ``"file"`` or ``"dir"`` if the value is a path that must exist.
    required_if : dict, optional
        The key is required only if all these keys of the section have the given values.
    check : callable, optional
        Additional check returning an error message or None.
    """

    def __init__(
        self,
        key: str,
        types: Union[type, Tuple[type, ...], None] = None,
        *,
        required: bool = True,
        default: Any = _MISSING,
        nullable: bool = False,
        choices: Optional[Iterable] = None,
        minimum: Optional[float] = None,
        maximum: Optional[float] = None,
        path: Optional[str] = None,
        required_if: Optional[Dict[str, Any]] = None,
        check: Optional[Callable[[Any], Optional[str]]] = None,
    ) -> None:
        """Initialize the requirement, see the class attributes."""

        if path not in (None, "file", "dir"):
            raise ValueError("Requirement path must be 'file' or 'dir'")
        if types is None:
            types = ()
        elif isinstance(types, type):
            types = (types,)
        self.key = key
        self.types = tuple(types)
        self.default = default
        self.required = required and default is _MISSING and required_if is None
        self.nullable = nullable or default is None
        self.choices = tuple(choices) if choices is not None else None
        self.minimum = minimum
        self.maximum = maximum
        self.path = path
        self.required_if = required_if or {}
        self.check = check

    @property
    def has_default(self) -> bool:
        """Return whether the requirement defines a default value."""

        return self.default is not _MISSING

    def is_required(self, section: dict) -> bool:
        """Return whether the key is required in the given section.

        Parameters
        ----------
        section : dict
            Configuration section.

        Returns
        -------
        bool
            True if the key must be present.
        """

        if self.required_if:
            return all(section.get(key) == value for key, value in self.required_if.items())
        return self.required

    def _type_error(self, value: Any) -> Optional[str]:
        """Return an error message if the value has a wrong type."""

        if not self.types:
            return None
        if isinstance(value, bool) and bool not in self.types:
            return f"expected {self._type_names()}, got bool"
        if not isinstance(value, self.types):
            return f"expected {self._type_names()}, got {type(value).__name__}"
        return None

    def _type_names(self) -> str:
        """Return the names of the accepted types."""

        return " or ".join(value_type.__name__ for value_type in self.types)

    def validate(self, section: dict) -> Optional[str]:
        """Check the requirement and set the default value.

        Parameters
        ----------
        section : dict
            Configuration section, modified in place by defaults.

        Returns
        -------
        str or None
            Error message, or None if the requirement is met.
        """

        if self.key not in section:
            if self.has_default:
                section[self.key] = self.default
                return None
            if self.is_required(section):
                return "missing required field"
            return None

        value = section[self.key]
        if value is None:
            return None if self.nullable or not self.is_required(section) else "must not be empty"

        error = self._type_error(value)
        if error:
            return error
        if self.choices is not None and value not in self.choices:
            return f"must be one of {', '.join(map(str, self.choices))}"
        if self.minimum is not None and value < self.minimum:
            return f"must be at least {self.minimum}"
        if self.maximum is not None and value > self.maximum:
            return f"must be at most {self.maximum}"
        if self.path == "file" and not Path(value).is_file():
            return f"file does not exist: {value}"
        if self.path == "dir" and not Path(value).is_dir():
            return f"directory does not exist: {value}"
        if self.check is not None:
            return self.check(value)
        return None


class Configurable:
    """Mixin of classes declaring the configuration they use.

    A class lists :class:`Requirement` objects in a class attribute (``REQUIREMENTS``
    by default). Requirements of base classes are inherited, a subclass may override a
    requirement by declaring the same key.
    """

    REQUIREMENTS: Tuple[Requirement, ...] = ()

    @classmethod
    def requirements(cls, attribute: str = "REQUIREMENTS") -> List[Requirement]:
        """Collect the requirements declared along the class hierarchy.

        Parameters
        ----------
        attribute : str, optional
            Class attribute holding the requirements, by default ``REQUIREMENTS``.

        Returns
        -------
        list
            Requirements, a subclass declaration overrides its bases.
        """

        collected = {}
        for klass in reversed(cls.__mro__):
            for requirement in vars(klass).get(attribute, ()):
                collected[requirement.key] = requirement
        return list(collected.values())

    @classmethod
    def check_config(cls, section: Any, owner: str, attribute: str = "REQUIREMENTS") -> dict:
        """Check a configuration section against the declared requirements.

        Parameters
        ----------
        section : dict
            Configuration section, defaults are set in place.
        owner : str
            Name of the section used in error messages, e.g. ``daf``.
        attribute : str, optional
            Class attribute holding the requirements, by default ``REQUIREMENTS``.

        Returns
        -------
        dict
            The checked section.

        Raises
        ------
        ConfigError
            If the section is not a mapping or a requirement is not met.
        """

        if not isinstance(section, dict):
            logger.error(f"Configuration section {owner} must be a mapping")
            raise ConfigError(f"{owner}: configuration section must be a mapping")

        requirements = cls.requirements(attribute)
        # Defaults first, so that conditional requirements see them.
        for requirement in requirements:
            if requirement.key not in section and requirement.has_default:
                section[requirement.key] = requirement.default

        errors = []
        for requirement in requirements:
            error = requirement.validate(section)
            if error:
                errors.append(f"{owner}.{requirement.key}: {error}")
        if errors:
            for error in errors:
                logger.error(error)
            raise ConfigError("; ".join(errors))
        return section


class ConfigLoader:
    """Load the DAF configuration file.

    Only the structure of the file is checked here. Every class using the
    configuration checks its own requirements, see :class:`Configurable`.

    Attributes
    ----------
    path : pathlib.Path
        Path to the YAML configuration file.
    """

    def __init__(self, path: Union[str, Path]) -> None:
        """Initialize the loader.

        Parameters
        ----------
        path : str or pathlib.Path
            Path to the YAML configuration file.
        """

        self.path = Path(path)

    def load(self, progress_print: bool = False) -> dict:
        """Read the configuration file.

        Parameters
        ----------
        progress_print : bool, optional
            Stored as the runtime field ``daf.progress_print``, enables progress logs.

        Returns
        -------
        dict
            Configuration with the ``daf`` section and module sections.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        ConfigError
            If the file is not valid YAML or its sections are not mappings.
        """

        if not self.path.exists():
            logger.error("Config file not found")
            raise FileNotFoundError("DAF:: config file not found")

        with self.path.open("r", encoding="utf-8") as file:
            try:
                config = yaml.safe_load(file)
            except yaml.YAMLError as error:
                logger.error("Config file is not valid YAML")
                raise ConfigError("DAF:: config file is not valid YAML") from error

        if not isinstance(config, dict) or not isinstance(config.get("daf"), dict):
            logger.error("Config file does not contain the daf section")
            raise ConfigError("DAF:: configuration of DAF module is missing in config file")
        for name, section in config.items():
            if not isinstance(section, dict):
                raise ConfigError(f"DAF:: configuration section {name} must be a mapping")

        config["daf"]["progress_print"] = progress_print
        return config


__all__ = ["ConfigError", "ConfigLoader", "Configurable", "Requirement"]
