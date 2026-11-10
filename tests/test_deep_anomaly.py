"""Tests for STEP 8 autoencoder / VAE detectors and the section-aware anomaly runner."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
import torch

from models.anomaly import build_detector
from models.deep_anomaly import AutoencoderDetector, VAEDetector
from models.train_anomaly import section_cfg

SMALL = {"hidden": [16, 8], "latent": 4, "epochs": 15, "batch_size": 128, "patience": 3, "lr": 0.005}


@pytest.fixture()
def manifold() -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Benign rows on a 2-D linear manifold in 10-D; attacks off the manifold."""
    rng = np.random.default_rng(0)
    W = rng.normal(size=(2, 10))
    benign = (rng.normal(size=(3000, 2)) @ W + 0.05 * rng.normal(size=(3000, 10))).astype(np.float32)
    val = (rng.normal(size=(500, 2)) @ W + 0.05 * rng.normal(size=(500, 10))).astype(np.float32)
    attack = (rng.normal(size=(200, 10)) * 2).astype(np.float32)
    return benign, val, attack


@pytest.mark.parametrize("cls", [AutoencoderDetector, VAEDetector])
def test_deep_detector_scores_off_manifold_flows_higher(cls, manifold):
    benign, val, attack = manifold
    det = cls(**SMALL, random_state=1).fit(benign, val)
    s_b, s_a = det.score(val), det.score(attack)
    assert np.isfinite(s_b).all() and np.isfinite(s_a).all()
    assert np.median(s_a) > np.quantile(s_b, 0.99)
    assert det.best_epoch_ is not None and len(det.history_) >= det.best_epoch_
    # early stopping keeps the best epoch's weights
    best_val = min(h["val_loss"] for h in det.history_)
    torch_val = float(np.mean(det.score(val[: len(val)])))
    if cls is AutoencoderDetector:  # val loss and score are the same quantity for the AE
        assert torch_val == pytest.approx(best_val, rel=1e-4)


def test_deep_detector_is_deterministic_and_roundtrips(tmp_path: Path, manifold):
    benign, val, attack = manifold
    a = VAEDetector(**SMALL, random_state=3).fit(benign, val)
    b = VAEDetector(**SMALL, random_state=3).fit(benign, val)
    np.testing.assert_allclose(a.score(attack), b.score(attack), rtol=1e-5)
    # scoring is deterministic (latent mean, no sampling) and chunking does not matter
    np.testing.assert_allclose(a.score(attack), a.score(attack))
    a.chunk_rows = 7
    np.testing.assert_allclose(a.score(attack), b.score(attack), rtol=1e-5)
    again = VAEDetector.load(a.save(tmp_path / "vae.joblib"))
    np.testing.assert_allclose(again.score(attack), b.score(attack), rtol=1e-5)
    with pytest.raises(TypeError):
        AutoencoderDetector.load(tmp_path / "vae.joblib")


def test_vae_recon_mode_and_validation(manifold):
    benign, val, attack = manifold
    det = VAEDetector(**{**SMALL, "epochs": 3}, score_mode="recon").fit(benign, val)
    rec = det.score(attack)
    det.score_mode = "elbo"
    assert (det.score(attack) >= rec - 1e-6).all()  # ELBO adds a non-negative KL term
    with pytest.raises(ValueError):
        VAEDetector(score_mode="bogus").fit(benign)
    with pytest.raises(ValueError):
        det.score(attack[:, :5])
    with pytest.raises(RuntimeError):
        AutoencoderDetector().score(attack)
    bad = benign.copy()
    bad[0, 0] = np.nan
    with pytest.raises(ValueError):
        AutoencoderDetector(**SMALL).fit(bad)


def test_fit_without_validation_uses_training_loss(manifold):
    benign, _, _ = manifold
    det = AutoencoderDetector(**{**SMALL, "epochs": 2}).fit(benign)
    assert all(h["val_loss"] == h["train_loss"] for h in det.history_)


def test_build_detector_and_section_inheritance():
    det = build_detector("autoencoder", {"latent": 3}, seed=7)
    assert isinstance(det, AutoencoderDetector) and det.latent == 3 and det.random_state == 7
    assert isinstance(build_detector("vae", {}), VAEDetector)
    cfg = {"models": {"anomaly": {"split": "by_day", "target_fpr": [0.01], "variants": ["a"]},
                      "deep_anomaly": {"base": "anomaly", "variants": ["b"]}}}
    sec = section_cfg(cfg, "deep_anomaly")
    assert sec["split"] == "by_day" and sec["variants"] == ["b"] and "base" not in sec
