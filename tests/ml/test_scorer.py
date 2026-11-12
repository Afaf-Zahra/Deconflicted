import datetime

import pytest

torch = pytest.importorskip("torch")

from deconflicted.ml import scorer as scorer_module
from deconflicted.ml.scorer import GRUScorer, ScorerError, train
from deconflicted.ml.train import main as train_main
from deconflicted.ml.train import read_days, sequences_from_lines
from deconflicted.schema import Scorer
from deconflicted.sim.roles import day_lines

ODD = ["auth:logon", "proc:powershell_enc", "proc:nltest", "net:decoy_touch", "log:cleared",
       "ot:write_setpoint", "proc:certutil_download", "net:smb_admin"]


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    out = tmp_path_factory.mktemp("weights")
    days = [day_lines(datetime.date(2026, 3, 1 + n), n) for n in range(2)]
    sequences = [seq for lines in days for seq in sequences_from_lines(lines)]
    report = train(sequences, out, epochs=4, seed=0)
    held_out = sequences_from_lines(day_lines(datetime.date(2026, 3, 9), 9))
    return out, report, held_out


def test_training_report_and_files(trained):
    out, report, _ = trained
    assert (out / "scorer.pt").exists() and (out / "vocab.json").exists()
    assert report.windows > 50 and report.vocab_size > 10 and report.final_loss < 1.5 and report.seconds < 120


def test_score_is_between_0_and_1_and_follows_the_protocol(trained):
    out, _, held_out = trained
    scorer = GRUScorer.load(out)
    assert isinstance(scorer, Scorer)
    for tokens in held_out:
        assert 0.0 <= scorer.score("user:x", tokens) <= 1.0


def test_same_weights_and_input_give_the_same_score(trained):
    out, _, held_out = trained
    first, second = GRUScorer.load(out), GRUScorer.load(out)
    tokens = max(held_out, key=len)
    assert first.score("a", tokens) == second.score("a", tokens) == first.score("a", tokens)


def test_unusual_sequences_score_higher_than_normal_ones(trained):
    out, _, held_out = trained
    scorer = GRUScorer.load(out)
    normal = [scorer.score("a", seq) for seq in held_out if len(seq) >= 2]
    odd = scorer.score("user:alice", ODD)
    assert odd > 0.95, f"the attack-like sequence scored {odd}"
    assert sum(normal) / len(normal) < 0.8, f"benign sequences averaged {sum(normal) / len(normal)}"
    assert odd > max(normal)


def test_unknown_tokens_and_short_inputs_do_not_crash(trained):
    scorer = GRUScorer.load(trained[0])
    assert scorer.score("a", ["made:up", "tokens:only"]) > 0.9
    assert scorer.score("a", []) == 0.0 and scorer.score("a", ["auth:logon"]) == 0.0
    assert 0 <= scorer.score("a", ["auth:logon", "proc:nltest"] * 40) <= 1, "only the last 20 tokens are used"


def test_missing_or_mismatched_files_raise_a_clear_error(trained, tmp_path):
    with pytest.raises(ScorerError):
        GRUScorer.load(tmp_path / "nowhere")
    out = trained[0]
    copy = tmp_path / "copy"
    copy.mkdir()
    (copy / "scorer.pt").write_bytes((out / "scorer.pt").read_bytes())
    (copy / "vocab.json").write_text('{"tokens": ["<pad>", "<unk>", "x"]}')
    with pytest.raises(ScorerError, match="does not belong"):
        GRUScorer.load(copy)
    (copy / "scorer.pt").write_bytes(b"garbage")
    with pytest.raises(ScorerError):
        GRUScorer.load(copy)


def test_training_is_deterministic(tmp_path):
    sequences = sequences_from_lines(day_lines(datetime.date(2026, 3, 1), 1))
    train(sequences, tmp_path / "a", epochs=2, seed=3)
    train(sequences, tmp_path / "b", epochs=2, seed=3)
    one, two = GRUScorer.load(tmp_path / "a"), GRUScorer.load(tmp_path / "b")
    assert one.benign == two.benign and one.score("a", ODD) == two.score("a", ODD)


def test_cannot_train_without_data(tmp_path):
    with pytest.raises(ScorerError):
        train([["auth:logon"]], tmp_path)


def test_train_cli(tmp_path, capsys):
    out = tmp_path / "out"
    assert train_main(["--simulate", "1", "--epochs", "1", "--out", str(out)]) == 0
    assert "trained on" in capsys.readouterr().out and (out / "scorer.pt").exists()
    assert train_main(["--out", str(out)]) == 1
    day = tmp_path / "days"
    day.mkdir()
    (day / "a.jsonl").write_text('{"source":"flow","raw":"x"}\nnot json\n')
    with pytest.raises(ScorerError):
        read_days(day)
    capsys.readouterr()


def test_default_weights_folder_is_inside_the_package():
    assert scorer_module.DEFAULT_DIR.name == "weights" and scorer_module.DEFAULT_DIR.parent.name == "ml"


def test_committed_weights_load_and_flag_an_attack_like_sequence():
    scorer = GRUScorer.load()
    assert scorer.score("user:alice", ODD) > 0.95
    held_out = sequences_from_lines(day_lines(datetime.date(2026, 3, 20), 42))
    normal = [scorer.score("x", seq) for seq in held_out if len(seq) >= 2]
    assert sum(normal) / len(normal) < 0.8, "the committed weights should treat a normal day as normal"


def test_committed_weights_are_plain_cpu_tensors():
    saved = torch.load(scorer_module.DEFAULT_DIR / "scorer.pt", map_location="cpu", weights_only=True)
    assert all(t.device.type == "cpu" and t.dtype == torch.float32 for t in saved["state_dict"].values())
    assert (scorer_module.DEFAULT_DIR / "scorer.pt").stat().st_size < 1_000_000, "small enough to commit"
