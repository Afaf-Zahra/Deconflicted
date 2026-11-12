import json

import httpx
import pytest

from deconflicted.sim import replay as rp

LINES = [
    {"source": "windows", "raw": json.dumps({"EventID": 1102, "UtcTime": f"2026-03-04T03:{m:02d}:{s:02d}.000Z",
                                              "Computer": "file-01", "SubjectUserName": "alice"})}
    for m, s in ((40, 0), (40, 1), (40, 2), (41, 1))
]


@pytest.fixture
def scenario(tmp_path):
    path = tmp_path / "scenario.jsonl"
    path.write_text("\n".join(json.dumps(item) for item in LINES) + "\n")
    return path


def test_batches_follow_log_time_divided_by_speed(scenario):
    events = rp.load(str(scenario))
    plan = list(rp.batches(events, speed=60, batch_seconds=1.0))
    assert [len(group) for _, group in plan] == [3, 1]
    assert [round(when, 4) for when, _ in plan] == [round(2 / 60, 4), round(61 / 60, 4)], \
        "a batch is sent when its last event is due"


def test_replay_waits_between_batches_and_sends_every_event(scenario):
    sent, slept, clock = [], [], [0.0]

    def sleep(seconds):
        slept.append(round(seconds, 4))
        clock[0] += seconds

    count = rp.replay(rp.load(str(scenario)), sent.append, speed=60, sleep=sleep, clock=lambda: clock[0])
    assert count == 2 and [len(g) for g in sent] == [3, 1]
    assert slept == [round(2 / 60, 4), round(59 / 60, 4)]
    assert [item for group in sent for item in group] == LINES


def test_speed_zero_sends_everything_at_once_in_batches(scenario):
    sent, slept = [], []
    rp.replay(rp.load(str(scenario)), sent.append, speed=0, batch_size=3, sleep=slept.append)
    assert [len(g) for g in sent] == [3, 1] and slept == [], "no waiting at speed 0"


def test_cli_posts_to_ingest_with_the_agreed_body(scenario, capsys):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"accepted": 3})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert rp.main(["--file", str(scenario), "--speed", "0", "--url", "http://api:8000/"], client=client) == 0
    assert [(m, p) for m, p, _ in seen] == [("POST", "/ingest")]
    assert seen[0][2] == {"events": LINES}
    assert "replayed 4 events in 1 batches" in capsys.readouterr().out


def test_cli_dry_run_prints_batches_and_sends_nothing(scenario, capsys):
    def handler(request):
        raise AssertionError("a dry run must not send anything")
    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert rp.main(["--file", str(scenario), "--speed", "60", "--dry-run"], client=client) == 0
    out, err = capsys.readouterr()
    assert [len(json.loads(line)["events"]) for line in out.splitlines()] == [3, 1]
    assert "replayed 4 events in 2 batches" in err


def test_cli_fails_on_a_server_error_bad_lines_and_disorder(scenario, tmp_path, capsys):
    failing = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500, text="boom")))
    assert rp.main(["--file", str(scenario), "--speed", "0"], client=failing) == 1
    assert "500" in capsys.readouterr().out
    down = httpx.Client(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("down"))))
    assert rp.main(["--file", str(scenario), "--speed", "0"], client=down) == 1
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps(LINES[0]) + "\nnot json\n")
    assert rp.main(["--file", str(bad), "--dry-run"]) == 1 and f"{bad}:2" in capsys.readouterr().out
    unordered = tmp_path / "unordered.jsonl"
    unordered.write_text(json.dumps(LINES[3]) + "\n" + json.dumps(LINES[0]) + "\n")
    assert rp.main(["--file", str(unordered), "--dry-run"]) == 1 and "time order" in capsys.readouterr().out
    assert rp.main(["--file", str(tmp_path / "missing.jsonl"), "--dry-run"]) == 1
    capsys.readouterr()


def test_empty_file_sends_nothing(tmp_path, capsys):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert rp.main(["--file", str(empty), "--dry-run"]) == 0
    capsys.readouterr()
