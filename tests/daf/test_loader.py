"""Tests of the module discovery and loading."""

import textwrap

import pytest

from config import ConfigError
from helpers import ANNOTATORS, daf_config, module
from loader import ModuleLoader

MODULE = textwrap.dedent(
    '''
    from core import IPAnnotator


    class SampleAnnotator(IPAnnotator):
        name = "sample_annotator"

        def annotate_ip(self, ip):
            pass
    '''
)


def write_module(root, name, source):
    folder = root / name
    folder.mkdir(parents=True)
    (folder / f"{name}.py").write_text(source)


def config_with_dirs(tmp_path, **sections):
    annotators = tmp_path / "annotators"
    detectors = tmp_path / "detectors"
    annotators.mkdir(parents=True)
    detectors.mkdir(parents=True)
    config = daf_config(**sections)
    config["daf"]["annotators_path"] = str(annotators)
    config["daf"]["detectors_path"] = str(detectors)
    return config, annotators


def test_load_creates_enabled_module_classes(tmp_path):
    config, annotators = config_with_dirs(
        tmp_path,
        sample_annotator={},
        other_annotator={"enabled": False},
    )
    write_module(annotators, "sample_annotator", MODULE)
    write_module(annotators, "other_annotator", MODULE.replace("sample_annotator", "other_annotator"))

    modules = ModuleLoader(config).load()

    assert [type(module).__name__ for module in modules] == ["SampleAnnotator"]


def test_load_from_explicit_path(tmp_path):
    path = tmp_path / "custom" / "sample_annotator.py"
    path.parent.mkdir()
    path.write_text(MODULE)
    config, _ = config_with_dirs(tmp_path, sample_annotator={"path": str(path)})

    assert [module.name for module in ModuleLoader(config).load()] == ["sample_annotator"]


def test_module_file_without_class_is_rejected(tmp_path):
    config, annotators = config_with_dirs(tmp_path, broken_annotator={})
    write_module(annotators, "broken_annotator", "def annotate(ip_addresses, config, data):\n    pass\n")

    with pytest.raises(ValueError, match="does not define"):
        ModuleLoader(config).load()


def test_module_sections_and_directories_are_checked(tmp_path):
    config, _ = config_with_dirs(tmp_path, sample_annotator={"enabled": "yes"})
    with pytest.raises(ConfigError, match="sample_annotator.enabled"):
        ModuleLoader(config)

    config, _ = config_with_dirs(tmp_path / "other")
    config["daf"]["detectors_path"] = str(tmp_path / "missing")
    with pytest.raises(ConfigError, match="daf.detectors_path"):
        ModuleLoader(config)


def test_import_file_registers_module(tmp_path):
    path = tmp_path / "pkg" / "thing.py"
    path.parent.mkdir()
    path.write_text("VALUE = 1\n")

    module = ModuleLoader.import_file(path)

    assert module.VALUE == 1
    assert ModuleLoader.import_file(path) is module


def test_modules_grouped_by_kind(tmp_path, caplog):
    config, annotators = config_with_dirs(tmp_path, sample_annotator={})
    write_module(annotators / "flow", "sample_annotator", MODULE)

    modules = ModuleLoader(config).load()

    assert [module.name for module in modules] == ["sample_annotator"]
    assert "ip-based module placed in the 'flow' folder" in caplog.text


def test_shipped_modules_match_their_folder():
    for kind in ("ip", "flow"):
        for file in ModuleLoader.module_files(ANNOTATORS / kind):
            klass = ModuleLoader.find_class(module(file), file.stem)
            assert klass is not None and klass.kind == kind, file
