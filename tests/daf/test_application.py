"""Tests of the DAF application and the command-line entry point."""

import logging
import shutil

import pandas as pd
import pytest

from config import ConfigError, ConfigLoader
from daf import DAFApplication, main
from helpers import ROOT

BASIC_CONFIG = "../examples/basic/daf_config_example.yml"


def copy_dataset(tmp_path):
    dataset = tmp_path / "example_dataset.csv"
    shutil.copy(ROOT / "examples" / "basic" / "example_dataset.csv", dataset)
    return dataset


def run_main(tmp_path, monkeypatch, config=BASIC_CONFIG):
    dataset = copy_dataset(tmp_path)
    monkeypatch.chdir(ROOT / "src")
    main(["--config", str(config), "--dataset", str(dataset), "--logfile", str(tmp_path / "daf.log")])
    return dataset


def test_main_runs_the_basic_example(tmp_path, monkeypatch):
    run_main(tmp_path, monkeypatch)

    annotated = pd.read_csv(tmp_path / "example_dataset_annotated.csv")
    assert len(annotated) == 865
    assert annotated["os_family"].notna().any()
    assert (tmp_path / "example_dataset_ip_data.json").is_file()
    log = (tmp_path / "daf.log").read_text()
    assert "Device Annotation Framework (DAF)" in log
    assert "Loaded annotators:" in log
    assert "Annotation finished in time" in log


def test_application_with_loaded_config(tmp_path, monkeypatch):
    dataset = copy_dataset(tmp_path)
    monkeypatch.chdir(ROOT / "src")
    arg = DAFApplication.parse_arguments(["--config", BASIC_CONFIG, "--dataset", str(dataset)])
    app = DAFApplication(arg, ConfigLoader(arg.config).load())

    app.run()

    assert {module.name for module in app.modules} >= {"sni_annotator", "mac_annotator"}
    assert type(app.create_runner()).__name__ == "DAFRunner"


def test_invalid_configuration_is_logged_and_stops_before_reading_data(tmp_path, monkeypatch):
    config = tmp_path / "config.yml"
    text = (ROOT / "examples" / "basic" / "daf_config_example.yml").read_text()
    config.write_text(text.replace("min_annotators_count: 2", "min_annotators_count: two"))

    with pytest.raises(ConfigError, match="daf.min_annotators_count"):
        run_main(tmp_path, monkeypatch, config)

    assert not (tmp_path / "example_dataset_annotated.csv").exists()
    log = (tmp_path / "daf.log").read_text()
    assert "daf.min_annotators_count: expected int" in log
    assert "DAF failed" in log


@pytest.mark.parametrize(
    "value, expected",
    [("True", True), ("true", True), ("False", False), ("none", False), ("run.log", "run.log")],
)
def test_logfile_argument(value, expected):
    arg = DAFApplication.parse_arguments(["--config", "c.yml", "--logfile", value])

    assert arg.logfile == expected


def test_logging_can_be_disabled_and_enabled_again(tmp_path):
    DAFApplication.setup_logging(False)
    assert logging.getLogger("DAF").isEnabledFor(logging.CRITICAL) is False

    DAFApplication.setup_logging(str(tmp_path / "again.log"))
    logging.getLogger("DAF").info("enabled again")
    logging.shutdown()

    assert "enabled again" in (tmp_path / "again.log").read_text()


def test_dataset_or_reannotation_is_required():
    arg = DAFApplication.parse_arguments(["--config", "config.yml"])

    with pytest.raises(ValueError, match="No dataset"):
        DAFApplication(arg, {"daf": {}}).load()
