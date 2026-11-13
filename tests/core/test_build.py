import hashlib
import json
from datetime import date
from pathlib import Path

from deconflicted import adapters
from deconflicted.adapters.common import make_id
from deconflicted.sim import replay
from deconflicted.sim.attack.script import ATTACK_DAY, attack_steps, distractor_steps
from deconflicted.sim.build import build_day, main

FIXTURES = json.loads((Path(__file__).parents[1] / "fixtures" / "events.json").read_text())
LABELED = [e for e in FIXTURES if e.get("label")]
DISTRACTOR_IDS = ["windows-784fdbff4513", "windows-6685e540534d", "windows-5433c7afb25f"]


def read(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ids_of(rows):
    return {make_id(r["source"], r["raw"]) for r in rows}


def test_the_main_attack_is_exactly_the_scenario_in_the_fixtures():
    steps = attack_steps()
    assert [s.raw for s in steps] == [e["raw"] for e in LABELED]
    assert [make_id(s.source, s.raw) for s in steps] == [e["id"] for e in LABELED]
    assert [s.step for s in steps] == [e["label"]["step"] for e in LABELED]


def test_every_step_time_matches_its_raw_line():
    for step in attack_steps() + distractor_steps():
        assert adapters.get(step.source).parse_line(step.raw).ts == step.ts


def test_the_distractor_is_the_unlabeled_svc_backup_activity():
    steps = distractor_steps()
    assert [make_id(s.source, s.raw) for s in steps] == DISTRACTOR_IDS
    assert all(s.step is None for s in steps)


def test_variants_repeat_and_stay_valid():
    assert attack_steps(variant=1) == attack_steps(variant=1)
    assert attack_steps(variant=1) != attack_steps() and attack_steps(variant=1) != attack_steps(variant=2)
    for variant in range(30):
        steps = attack_steps(variant=variant)
        times = [s.ts for s in steps]
        assert times == sorted(times) and all(t.date() == ATTACK_DAY for t in times), variant
        assert [s.step for s in steps] == [1, 2, 3, 3, 7, 9]
        assert 61 <= json.loads(steps[5].raw)["value"] <= 100, variant


def test_build_day_mixes_the_attack_into_a_sorted_day():
    rows = build_day(date(2026, 3, 4), 1, attack_steps())
    times = [r[0] for r in rows]
    assert times == sorted(times) and len(rows) > 15000
    assert [r[3] for r in rows if r[3] is not None] == [1, 2, 3, 3, 7, 9]


def test_main_writes_the_files_the_rest_of_the_project_reads(tmp_path):
    assert main(["--out", str(tmp_path), "--benign-days", "2"]) == 0
    assert sorted(p.name for p in (tmp_path / "benign").iterdir()) == ["2026-03-02.jsonl", "2026-03-03.jsonl"]
    scenario, labels = read(tmp_path / "demo" / "scenario.jsonl"), read(tmp_path / "demo" / "labels.jsonl")
    assert [(l["id"], l["step"]) for l in labels] == [(e["id"], e["label"]["step"]) for e in LABELED]
    assert all(l["id"] in ids_of(scenario) for l in labels)
    assert not any(set(r) - {"source", "raw"} for r in scenario), "no label may travel with the events"
    assert len(replay.load(str(tmp_path / "demo" / "scenario.jsonl"))) == len(scenario)
    assert not (tmp_path / "demo" / "scenario_full.jsonl").exists()


def test_main_is_repeatable_and_options_change_the_output(tmp_path):
    one, two, three = tmp_path / "one", tmp_path / "two", tmp_path / "three"
    for out in (one, two):
        main(["--out", str(out), "--benign-days", "1", "--full"])
    main(["--out", str(three), "--benign-days", "1", "--variant", "5", "--seed", "2"])
    for name in ("benign/2026-03-03.jsonl", "demo/scenario.jsonl", "demo/labels.jsonl", "demo/scenario_full.jsonl"):
        assert digest(one / name) == digest(two / name), name
    assert digest(one / "demo/scenario.jsonl") != digest(three / "demo/scenario.jsonl")


def test_the_window_option_and_the_distractor_switch(tmp_path):
    main(["--out", str(tmp_path / "a"), "--benign-days", "0", "--window", "01:00-02:00"])
    assert set(DISTRACTOR_IDS) <= ids_of(read(tmp_path / "a" / "demo" / "scenario.jsonl"))
    main(["--out", str(tmp_path / "b"), "--benign-days", "0", "--window", "01:00-02:00", "--no-distractors"])
    assert not set(DISTRACTOR_IDS) & ids_of(read(tmp_path / "b" / "demo" / "scenario.jsonl"))