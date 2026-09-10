"""Shared fixtures of the DAF unit tests."""

import pytest

from annotation import Annotation
from helpers import ROOT


@pytest.fixture(scope="session", autouse=True)
def taxonomy() -> None:
    """Initialize the shared taxonomy checker with the shipped taxonomies."""

    Annotation.initialize_taxonomy_checker(
        str(ROOT / "taxonomies" / "os_taxonomy.json"),
        str(ROOT / "taxonomies" / "dev_taxonomy.json"),
    )
