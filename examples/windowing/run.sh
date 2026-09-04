#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "${script_dir}/../../src"

uv run --extra nat_detector ./daf.py \
    --config ../examples/windowing/daf_config_example.yml \
    --dataset ../examples/windowing/example_dataset.csv \
    --logfile ../examples/windowing/daf_example.log
