# -*- coding: utf-8 -*-
import os
import sys
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('TF_CPP_MIN_LOG_LEVEL', '2')
warnings.filterwarnings('ignore')


@pytest.fixture(scope='session')
def artifacts():
    from core.model_loader import load_artifacts
    art = load_artifacts()
    assert not art.errors, art.errors
    return art


@pytest.fixture(scope='session')
def predictor(artifacts):
    from core.predictor import Predictor
    return Predictor(artifacts)
