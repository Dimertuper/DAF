"""Tests of the configuration requirements and loading."""

import pytest
import yaml

from config import ConfigError, ConfigLoader, Configurable, Requirement


class Base(Configurable):
    REQUIREMENTS = (
        Requirement("name", str),
        Requirement("count", int, default=1, minimum=0),
    )


class Child(Base):
    REQUIREMENTS = (
        Requirement("count", int, default=5, maximum=10),
        Requirement("mode", str, default="a", choices=("a", "b")),
        Requirement("path", str, required_if={"mode": "b"}),
    )


def test_defaults_are_set_into_the_section():
    section = {"name": "x"}

    assert Child.check_config(section, "child") is section
    assert section == {"name": "x", "count": 5, "mode": "a"}


def test_requirements_are_inherited_and_overridden():
    keys = [requirement.key for requirement in Child.requirements()]

    assert keys == ["name", "count", "mode", "path"]
    assert Child.requirements()[1].default == 5


@pytest.mark.parametrize(
    "section, message",
    [
        ({}, "child.name: missing required field"),
        ({"name": 1}, "child.name: expected str, got int"),
        ({"name": "x", "count": True}, "child.count: expected int, got bool"),
        ({"name": "x", "count": 11}, "child.count: must be at most 10"),
        ({"name": "x", "mode": "c"}, "child.mode: must be one of a, b"),
        ({"name": "x", "mode": "b"}, "child.path: missing required field"),
        ({"name": None}, "child.name: must not be empty"),
    ],
)
def test_invalid_sections(section, message):
    with pytest.raises(ConfigError, match=message):
        Child.check_config(section, "child")


def test_all_errors_are_reported():
    with pytest.raises(ConfigError) as error:
        Child.check_config({"count": 11, "mode": "c"}, "child")

    assert str(error.value).count(";") == 2


def test_path_and_custom_checks(tmp_path):
    existing = tmp_path / "file.csv"
    existing.write_text("")

    class Paths(Configurable):
        REQUIREMENTS = (
            Requirement("file", str, path="file"),
            Requirement("dir", str, path="dir"),
            Requirement("even", int, check=lambda value: None if value % 2 == 0 else "must be even"),
        )

    Paths.check_config({"file": str(existing), "dir": str(tmp_path), "even": 2}, "paths")
    with pytest.raises(ConfigError, match="file does not exist"):
        Paths.check_config({"file": "missing", "dir": str(tmp_path), "even": 2}, "paths")
    with pytest.raises(ConfigError, match="must be even"):
        Paths.check_config({"file": str(existing), "dir": str(tmp_path), "even": 3}, "paths")


def test_nullable_and_optional_keys():
    class Optional_(Configurable):
        REQUIREMENTS = (
            Requirement("dst", str, default=None),
            Requirement("extra", str, required=False),
        )

    section = {}
    Optional_.check_config(section, "optional")
    assert section == {"dst": None}


def test_section_must_be_a_mapping():
    with pytest.raises(ConfigError, match="mapping"):
        Base.check_config(["name"], "base")


def test_config_loader(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text(yaml.safe_dump({"daf": {"threads": True}, "hand_annotator": {"enabled": False}}))

    config = ConfigLoader(path).load(progress_print=True)

    assert config["daf"] == {"threads": True, "progress_print": True}


@pytest.mark.parametrize("content", ["daf: [", "hand_annotator: {}", "daf: {}\nother: 1"])
def test_config_loader_rejects_invalid_files(tmp_path, content):
    path = tmp_path / "config.yml"
    path.write_text(content)

    with pytest.raises(ConfigError):
        ConfigLoader(path).load()


def test_config_loader_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        ConfigLoader(tmp_path / "missing.yml").load()
