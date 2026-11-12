"""A small GRU that predicts the next behaviour token. Unusual sequences get a high score (0 to 1).

CPU only, fixed seeds, no network. The saved files are small and are committed with the code.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import random
import time
from dataclasses import dataclass
from pathlib import Path

import torch
from torch import nn

PAD, UNK = "<pad>", "<unk>"
WINDOW = 20                      # tokens the score looks at
EMBED, HIDDEN = 16, 32
DEFAULT_DIR = Path(__file__).parent / "weights"


class ScorerError(RuntimeError):
    """The scorer cannot be used. The detection core then runs without it."""


def _configure() -> None:
    torch.set_num_threads(2)
    torch.use_deterministic_algorithms(True)


class NextToken(nn.Module):
    def __init__(self, vocab_size: int):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, EMBED, padding_idx=0)
        self.gru = nn.GRU(EMBED, HIDDEN, batch_first=True)
        self.out = nn.Linear(HIDDEN, vocab_size)

    def forward(self, ids: torch.Tensor) -> torch.Tensor:
        hidden, _ = self.gru(self.embed(ids))
        return self.out(hidden)


def _vocab_hash(tokens: list[str]) -> str:
    return hashlib.sha256(json.dumps(tokens).encode()).hexdigest()


def _windows(ids: list[int], stride: int = 5) -> list[list[int]]:
    if len(ids) < 2:
        return []
    size = min(WINDOW, len(ids))
    starts = list(range(0, len(ids) - size + 1, stride))
    if starts[-1] != len(ids) - size:
        starts.append(len(ids) - size)
    return [ids[s:s + size] for s in starts]


def _nll(model: NextToken, ids: list[int]) -> float:
    x = torch.tensor([ids], dtype=torch.long)
    with torch.no_grad():
        logp = torch.log_softmax(model(x[:, :-1]), dim=-1)
        return float(-logp.gather(2, x[:, 1:].unsqueeze(-1)).mean())


class GRUScorer:
    """Implements the Scorer protocol: score(entity_id, tokens) -> float between 0 and 1."""

    def __init__(self, model: NextToken, vocab: list[str], benign_nll: list[float]):
        self.model, self.vocab, self.benign = model.eval(), vocab, sorted(benign_nll)
        self._index = {t: i for i, t in enumerate(vocab)}

    @classmethod
    def load(cls, directory: str | Path | None = None) -> "GRUScorer":
        base = Path(directory) if directory else DEFAULT_DIR
        try:
            vocab = json.loads((base / "vocab.json").read_text(encoding="utf-8"))["tokens"]
            saved = torch.load(base / "scorer.pt", map_location="cpu", weights_only=True)
            if saved["vocab_sha256"] != _vocab_hash(vocab):
                raise ScorerError("vocab.json does not belong to scorer.pt")
            model = NextToken(len(vocab))
            model.load_state_dict(saved["state_dict"])
            benign = [float(x) for x in saved["benign_nll"]]
        except ScorerError:
            raise
        except Exception as exc:
            raise ScorerError(f"cannot load the scorer from {base}: {exc}") from exc
        if not benign:
            raise ScorerError("the scorer file has no benign reference scores")
        _configure()
        return cls(model, vocab, benign)

    def score(self, entity_id: str, tokens: list[str]) -> float:
        """How unusual the last tokens are: the share of normal windows that look more normal."""
        ids = [self._index.get(t, 1) for t in tokens[-WINDOW:]]
        if len(ids) < 2:
            return 0.0  # nothing to judge, so no anomaly
        return bisect.bisect_left(self.benign, _nll(self.model, ids)) / len(self.benign)


@dataclass
class TrainReport:
    sequences: int
    windows: int
    vocab_size: int
    epochs: int
    final_loss: float
    seconds: float


def train(sequences: list[list[str]], out_dir: str | Path, epochs: int = 8, lr: float = 0.01,
          seed: int = 0, batch_size: int = 64) -> TrainReport:
    """Train on benign token sequences and write scorer.pt and vocab.json to out_dir."""
    started = time.time()
    _configure()
    torch.manual_seed(seed)
    seen = sorted({t for seq in sequences for t in seq})
    vocab = [PAD, UNK] + seen
    index = {t: i for i, t in enumerate(vocab)}
    windows = [w for seq in sequences for w in _windows([index[t] for t in seq])]
    if not windows:
        raise ScorerError("no benign sequence is long enough to train on")
    model = NextToken(len(vocab))
    optimiser = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss(ignore_index=0)
    shuffler = random.Random(seed)
    loss_value = 0.0
    for _ in range(epochs):
        order = list(range(len(windows)))
        shuffler.shuffle(order)
        for start in range(0, len(order), batch_size):
            batch = [windows[i] for i in order[start:start + batch_size]]
            width = max(len(w) for w in batch)
            x = torch.tensor([w + [0] * (width - len(w)) for w in batch], dtype=torch.long)
            loss = loss_fn(model(x[:, :-1]).reshape(-1, len(vocab)), x[:, 1:].reshape(-1))
            optimiser.zero_grad()
            loss.backward()
            optimiser.step()
            loss_value = loss.item()
    model.eval()
    benign = [_nll(model, w) for w in windows]
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "vocab.json").write_text(json.dumps({"tokens": vocab}, indent=1), encoding="utf-8")
    torch.save({"state_dict": model.state_dict(), "benign_nll": benign, "vocab_sha256": _vocab_hash(vocab),
                "config": {"embed": EMBED, "hidden": HIDDEN, "window": WINDOW, "epochs": epochs, "seed": seed}},
               out / "scorer.pt")
    return TrainReport(len(sequences), len(windows), len(vocab), epochs, loss_value, time.time() - started)
