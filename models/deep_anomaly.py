"""Deep anomaly detectors trained on benign traffic (STEP 8): Autoencoder and VAE.

Same interface as :mod:`models.anomaly` - ``fit``, ``score`` (higher = more
anomalous), ``save`` / ``load`` - so STEP 6's runner, thresholds and metrics
apply unchanged. Both detectors accept benign validation rows in ``fit`` for
early stopping on validation loss; attack labels are never used.

* :class:`AutoencoderDetector` - fully connected autoencoder; score = mean
  squared reconstruction error per flow.
* :class:`VAEDetector` - variational autoencoder (Gaussian latent, fixed-variance
  Gaussian decoder); score = per-flow negative ELBO (reconstruction + beta * KL)
  with the latent mean, or the reconstruction term only (``score="recon"``).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import torch
from torch import nn

logger = logging.getLogger(__name__)


def _mlp(sizes: list[int], last_activation: bool) -> nn.Sequential:
    layers: list[nn.Module] = []
    for i in range(len(sizes) - 1):
        layers.append(nn.Linear(sizes[i], sizes[i + 1]))
        if i < len(sizes) - 2 or last_activation:
            layers.append(nn.ReLU())
    return nn.Sequential(*layers)


class _AE(nn.Module):
    def __init__(self, d: int, hidden: list[int], latent: int) -> None:
        super().__init__()
        self.encoder = _mlp([d, *hidden, latent], last_activation=False)
        self.decoder = _mlp([latent, *reversed(hidden), d], last_activation=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class _VAE(nn.Module):
    def __init__(self, d: int, hidden: list[int], latent: int) -> None:
        super().__init__()
        self.body = _mlp([d, *hidden], last_activation=True)
        self.mu = nn.Linear(hidden[-1], latent)
        self.logvar = nn.Linear(hidden[-1], latent)
        self.decoder = _mlp([latent, *reversed(hidden), d], last_activation=False)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        h = self.body(x)
        mu, logvar = self.mu(h), self.logvar(h).clamp(-10.0, 10.0)
        z = mu + torch.randn_like(mu) * torch.exp(0.5 * logvar) if self.training else mu
        return self.decoder(z), mu, logvar


@dataclass
class _DeepDetector:
    """Shared training loop: Adam, mini-batches, early stopping on benign validation loss.

    Args:
        hidden: Hidden layer widths of the encoder (decoder mirrors them).
        latent: Latent dimension.
        epochs: Maximum epochs.
        batch_size: Mini-batch size.
        lr: Adam learning rate.
        weight_decay: Adam weight decay.
        patience: Epochs without validation improvement before stopping.
        val_rows: Cap on benign validation rows used for early stopping.
        clip: Inputs are clipped to ``[-clip, clip]`` (scaled units) before
            the network, so a few extreme flows cannot dominate the loss.
        threads: Torch CPU threads (0 = torch default).
        random_state: Seed for weight init, shuffling and VAE sampling.
        chunk_rows: Rows per scoring batch.
    """

    hidden: list[int] = field(default_factory=lambda: [64, 32])
    latent: int = 16
    epochs: int = 30
    batch_size: int = 1024
    lr: float = 1e-3
    weight_decay: float = 0.0
    patience: int = 3
    val_rows: int = 100_000
    clip: float = 20.0
    threads: int = 0
    random_state: int = 42
    chunk_rows: int = 100_000
    model_: nn.Module | None = field(default=None, repr=False)
    n_features_: int | None = None
    history_: list[dict[str, float]] = field(default_factory=list)
    best_epoch_: int | None = None
    uses_validation = True  # the runner passes benign validation rows to fit()

    # subclasses implement these two
    def _build(self, d: int) -> nn.Module:
        raise NotImplementedError

    def _row_loss(self, model: nn.Module, x: torch.Tensor) -> torch.Tensor:
        raise NotImplementedError

    def _tensor(self, X: np.ndarray) -> torch.Tensor:
        return torch.from_numpy(np.clip(np.asarray(X, dtype=np.float32), -self.clip, self.clip))

    def fit(self, X: np.ndarray, X_val: np.ndarray | None = None) -> "_DeepDetector":
        X = np.asarray(X, dtype=np.float32)
        if X.ndim != 2 or len(X) < 2 or not np.isfinite(X).all():
            raise ValueError("Need a finite 2-D training array with at least 2 rows")
        if self.threads:
            torch.set_num_threads(int(self.threads))
        torch.manual_seed(self.random_state)
        rng = np.random.default_rng(self.random_state)
        self.n_features_ = X.shape[1]
        model = self._build(self.n_features_)
        opt = torch.optim.Adam(model.parameters(), lr=self.lr, weight_decay=self.weight_decay)
        Xt = self._tensor(X)
        Xv = None
        if X_val is not None and len(X_val):
            Xv_np = np.asarray(X_val, dtype=np.float32)
            if len(Xv_np) > self.val_rows:
                Xv_np = Xv_np[np.sort(rng.choice(len(Xv_np), self.val_rows, replace=False))]
            Xv = self._tensor(Xv_np)

        best, best_state, bad = np.inf, None, 0
        self.history_ = []
        for epoch in range(1, int(self.epochs) + 1):
            t0 = time.perf_counter()
            model.train()
            perm = torch.from_numpy(rng.permutation(len(Xt)))
            total = 0.0
            for s in range(0, len(Xt), self.batch_size):
                xb = Xt[perm[s:s + self.batch_size]]
                loss = self._row_loss(model, xb).mean()
                opt.zero_grad()
                loss.backward()
                opt.step()
                total += float(loss.detach()) * len(xb)
            train_loss = total / len(Xt)
            val_loss = float(self._score_tensor(model, Xv).mean()) if Xv is not None else train_loss
            self.history_.append({"epoch": epoch, "train_loss": train_loss, "val_loss": val_loss,
                                  "seconds": time.perf_counter() - t0})
            logger.info("%s epoch %d: train %.5f, val %.5f (%.1fs)", type(self).__name__, epoch, train_loss,
                        val_loss, self.history_[-1]["seconds"])
            if not np.isfinite(train_loss):
                raise FloatingPointError(f"Training diverged at epoch {epoch}")
            if val_loss < best - 1e-6:
                best, bad, self.best_epoch_ = val_loss, 0, epoch
                best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            else:
                bad += 1
                if bad >= self.patience:
                    break
        if best_state is not None:
            model.load_state_dict(best_state)
        model.eval()
        self.model_ = model
        return self

    def _score_tensor(self, model: nn.Module, X: torch.Tensor) -> torch.Tensor:
        was_training = model.training
        model.eval()
        out = []
        with torch.no_grad():
            for s in range(0, len(X), self.chunk_rows):
                out.append(self._row_loss(model, X[s:s + self.chunk_rows]))
        model.train(was_training)
        return torch.cat(out)

    def score(self, X: np.ndarray) -> np.ndarray:
        if self.model_ is None:
            raise RuntimeError("Detector is not fitted")
        if np.asarray(X).ndim != 2 or X.shape[1] != self.n_features_:
            raise ValueError(f"Expected {self.n_features_} features, got shape {np.shape(X)}")
        out = np.empty(len(X), dtype=np.float64)
        with torch.no_grad():
            for s in range(0, len(X), self.chunk_rows):
                xb = self._tensor(X[s:s + self.chunk_rows])
                out[s:s + len(xb)] = self._row_loss(self.model_, xb).double().numpy()
        return out

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @classmethod
    def load(cls, path: str | Path) -> Any:
        obj = joblib.load(path)
        if not isinstance(obj, cls):
            raise TypeError(f"{path} does not contain a {cls.__name__}")
        return obj


@dataclass
class AutoencoderDetector(_DeepDetector):
    """Autoencoder; score = mean squared reconstruction error per flow."""

    def _build(self, d: int) -> nn.Module:
        return _AE(d, list(self.hidden), int(self.latent))

    def _row_loss(self, model: nn.Module, x: torch.Tensor) -> torch.Tensor:
        return ((model(x) - x) ** 2).mean(dim=1)


@dataclass
class VAEDetector(_DeepDetector):
    """Variational autoencoder; score = negative ELBO (``score="elbo"``) or reconstruction error.

    Args:
        beta: Weight of the KL term (``beta=1`` is the standard VAE).
        score_mode: ``"elbo"`` or ``"recon"``.
    """

    beta: float = 1.0
    score_mode: str = "elbo"

    def _build(self, d: int) -> nn.Module:
        if self.score_mode not in ("elbo", "recon"):
            raise ValueError(f"score_mode must be 'elbo' or 'recon', got {self.score_mode!r}")
        return _VAE(d, list(self.hidden), int(self.latent))

    def _row_loss(self, model: nn.Module, x: torch.Tensor) -> torch.Tensor:
        recon, mu, logvar = model(x)
        rec = ((recon - x) ** 2).mean(dim=1)
        if not model.training and self.score_mode == "recon":
            return rec
        kl = -0.5 * (1 + logvar - mu.pow(2) - logvar.exp()).sum(dim=1) / x.shape[1]
        return rec + self.beta * kl
