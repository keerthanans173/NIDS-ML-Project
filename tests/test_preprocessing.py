"""
Unit tests for SentinelFlow Data Pipeline & Feature Preprocessing
"""

import pytest
import numpy as np
import pandas as pd
from app.ml.preprocess import (
    ALL_FEATURES, CAT_FEATURES, CLASS_NAMES,
    map_raw_label, SentinelDataPipeline, PRESETS
)

def test_map_raw_label():
    assert map_raw_label("normal") == "Normal"
    assert map_raw_label("neptune") == "DoS"
    assert map_raw_label("smurf") == "DoS"
    assert map_raw_label("satan") == "Probe"
    assert map_raw_label("nmap") == "Probe"
    assert map_raw_label("guess_passwd") == "R2L"
    assert map_raw_label("ftp_write") == "R2L"
    assert map_raw_label("buffer_overflow") == "U2R"
    assert map_raw_label("rootkit") == "U2R"
    # Unseen fallback
    assert map_raw_label("unknown_crazy_attack") == "DoS"

def test_pipeline_transform_single():
    pipeline = SentinelDataPipeline()
    # Dummy fit on preset
    df = pd.DataFrame([PRESETS["Normal"], PRESETS["DoS"]])
    pipeline.fit(df[ALL_FEATURES], pd.Series(["Normal", "DoS"]))

    scaled = pipeline.transform_single(PRESETS["Normal"])
    assert scaled.shape == (1, 41)
    assert not np.isnan(scaled).any()

def test_pipeline_unseen_categorical():
    pipeline = SentinelDataPipeline()
    df = pd.DataFrame([PRESETS["Normal"], PRESETS["DoS"]])
    pipeline.fit(df[ALL_FEATURES], pd.Series(["Normal", "DoS"]))

    # Pass unseen protocol and service
    weird_sample = PRESETS["Normal"].copy()
    weird_sample["protocol_type"] = "alien_protocol_xyz"
    weird_sample["service"] = "nonexistent_port_999"

    scaled = pipeline.transform_single(weird_sample)
    assert scaled.shape == (1, 41)
    assert not np.isnan(scaled).any()
