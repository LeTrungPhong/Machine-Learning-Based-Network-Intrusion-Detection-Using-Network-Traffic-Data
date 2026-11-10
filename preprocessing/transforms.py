"""Element-wise transforms used inside fitted (pickled) preprocessing pipelines.

They live in their own module so a pickled pipeline always refers to
``preprocessing.transforms.<name>``. A function defined in a script run with
``python -m`` is pickled as ``__main__.<name>`` and cannot be loaded from any
other entry point.
"""

from __future__ import annotations

import numpy as np


def signed_log1p(x: np.ndarray) -> np.ndarray:
    """``sign(x) * log1p(|x|)``; keeps the -1 sentinel distinguishable from 0."""
    return np.sign(x) * np.log1p(np.abs(x))
