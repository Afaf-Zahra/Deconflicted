import pytest

from deconflicted.ledger import ConfigIntegrity, QuorumError, load_policy
from deconflicted.ledger.cli import main as cli_main
from deconflicted.ledger import service
from deconflicted.response import ResponseGuard
from deconflicted.schema import Action

from .conftest import make_ledger

PROTECTED = "config/safety_rules.yaml"


@pytest.fixture
def setup(tmp_path, config_copy):
    ledger = make_ledger(tmp_path / "nodes", load_policy(config_copy / "config" / "policy.yaml"))
    integrity = ConfigIntegrity(ledger.client, ledger.policy, root=config_copy)
    return ledger, integrity, config_copy


def test_first_start_anchors_the_config(setup):
    ledger, integrity, _ = setup
    assert integrity.problems() == ["no config anchor exists in the ledger yet"]
    entry = integrity.ensure_anchor()
    assert entry.kind == "config_anchor" and integrity.ensure_anchor() is None
    assert integrity.problems() == [] and integrity.check() == []
    assert set(ledger.client.payloads("config_anchor")[0][1]["files"]) == set(ledger.policy.protected_files)


def test_an_unsigned_change_raises_an_integrity_violation_once(setup):
    ledger, integrity, root = setup
    integrity.ensure_anchor()
    path = root / PROTECTED
    path.write_text(path.read_text().replace("max: 80", "max: 100"))
    [signal] = integrity.check()
    assert signal.kind == "integrity_violation" and signal.score == 1.0
    assert signal.detail["problems"] == [f"{PROTECTED} does not match the ledger"]
    before = ledger.client.count()
    assert len(integrity.check()) == 1 and ledger.client.count() == before, "the same problem is recorded only once"
    assert ledger.client.verify().ok


def test_the_guard_blocks_while_a_safety_file_is_unsigned(setup):
    ledger, integrity, root = setup
    integrity.ensure_anchor()
    guard = ResponseGuard(str(root / "config"), integrity_check=integrity.guard_check())
    action = Action(id="a", kind="disable_account", target="alice")
    state = {"level": 50.0, "setpoint": 50.0, "pump": False, "valve": 50.0}
    assert guard.preview(action, state).decision == "allow"
    path = root / PROTECTED
    path.write_text(path.read_text().replace("max: 80", "max: 100"))
    blocked = guard.preview(action, state)
    assert blocked.decision == "block" and "integrity" in blocked.reason


def test_the_guard_blocks_when_the_ledger_has_no_anchor(setup):
    _, integrity, _ = setup
    ok, why = integrity.guard_check()()
    assert not ok and "no config anchor" in why


def test_a_signed_policy_change_makes_the_edit_legitimate(setup):
    ledger, integrity, root = setup
    integrity.ensure_anchor()
    path = root / PROTECTED
    path.write_text(path.read_text().replace("max: 80", "max: 90"))
    assert integrity.problems()
    entry = integrity.propose_change(PROTECTED)
    assert entry.kind == "policy_change" and len(entry.signatures) >= 2
    assert integrity.problems() == [] and integrity.guard_check()() == (True, "")
    assert integrity.check() == []
    with pytest.raises(ValueError):
        integrity.propose_change("config/hosts.yaml")


def test_one_compromised_node_cannot_approve_a_policy_change(setup):
    ledger, integrity, root = setup
    integrity.ensure_anchor()
    path = root / PROTECTED
    path.write_text(path.read_text().replace("max: 80", "max: 100"))
    ledger.switches["node-b"].down = ledger.switches["node-c"].down = True
    with pytest.raises(QuorumError):
        integrity.propose_change(PROTECTED)
    assert integrity.problems(), "the change stays unapproved"


def test_a_missing_protected_file_is_a_problem(setup):
    _, integrity, root = setup
    integrity.ensure_anchor()
    (root / "config" / "decoys.yaml").unlink()
    assert integrity.problems() == ["config/decoys.yaml does not match the ledger"]


def test_cli_commands(tmp_path, config_copy, monkeypatch, capsys):
    ledger = make_ledger(tmp_path / "nodes", load_policy(config_copy / "config" / "policy.yaml"))
    integrity = ConfigIntegrity(ledger.client, ledger.policy, root=config_copy)
    monkeypatch.setattr(service, "_client", ledger.client)
    monkeypatch.setattr(service, "_integrity", integrity)
    assert cli_main(["check"]) == 1 and "no config anchor" in capsys.readouterr().out
    assert cli_main(["anchor-config"]) == 0 and "config anchored" in capsys.readouterr().out
    assert cli_main(["anchor-config"]) == 0 and "already exists" in capsys.readouterr().out
    assert cli_main(["check"]) == 0
    path = config_copy / PROTECTED
    path.write_text(path.read_text() + "\n# edited\n")
    assert cli_main(["check"]) == 1
    assert cli_main(["propose-change", PROTECTED]) == 0 and "policy_change recorded" in capsys.readouterr().out
    assert cli_main(["propose-change", "config/hosts.yaml"]) == 1
    assert cli_main(["status"]) == 0 and "verify ok=True" in capsys.readouterr().out
    assert cli_main([]) == 1 and cli_main(["nonsense"]) == 1
    capsys.readouterr()


def test_cli_fails_closed_without_a_ledger(monkeypatch, capsys):
    for name in ("DECONFLICTED_LEDGER_NODES", "DECONFLICTED_LEDGER_EMBEDDED"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(service, "_client", None)
    monkeypatch.setattr(service, "_integrity", None)
    assert cli_main(["status"]) == 1 and "FAILED" in capsys.readouterr().out


def test_a_change_made_while_the_api_was_down_is_recorded_at_start(tmp_path, config_copy, monkeypatch):
    ledger = make_ledger(tmp_path / "nodes", load_policy(config_copy / "config" / "policy.yaml"))
    ConfigIntegrity(ledger.client, ledger.policy, root=config_copy).ensure_anchor()
    path = config_copy / PROTECTED
    path.write_text(path.read_text().replace("max: 80", "max: 100"))
    monkeypatch.setenv("DECONFLICTED_CONFIG_DIR", str(config_copy / "config"))
    monkeypatch.setattr(service, "_client", ledger.client)
    monkeypatch.setattr(service, "_integrity", None)
    shared = service.get_integrity()
    detections = [p for _, p in ledger.client.payloads("detection")]
    assert [d["signal"]["kind"] for d in detections] == ["integrity_violation"]
    assert shared.problems(), "the change is still unsigned"
    assert service.get_integrity() is shared and len(ledger.client.payloads("detection")) == 1, "recorded once"


def test_build_client_from_the_environment(tmp_path, monkeypatch):
    from deconflicted.ledger import QuorumError
    for name in ("DECONFLICTED_LEDGER_NODES", "DECONFLICTED_LEDGER_EMBEDDED"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DECONFLICTED_LEDGER_DB", str(tmp_path / "client.db"))
    with pytest.raises(service.LedgerUnavailable, match="no ledger nodes"):
        service.build_client()
    monkeypatch.setenv("DECONFLICTED_LEDGER_NODES", "node-a=http://127.0.0.1:1,node-b=http://127.0.0.1:1")
    with pytest.raises(service.LedgerUnavailable, match="does not match"):
        service.build_client()
    monkeypatch.setenv("DECONFLICTED_LEDGER_NODES",
                       "node-a=http://127.0.0.1:1,node-b=http://127.0.0.1:1,node-c=http://127.0.0.1:1")
    client = service.build_client()
    assert [n.up for n in client.node_status()] == [False, False, False]
    with pytest.raises(QuorumError):
        client.append("detection", {"x": 1})
    client.close()
    monkeypatch.delenv("DECONFLICTED_LEDGER_NODES")
    monkeypatch.setenv("DECONFLICTED_LEDGER_EMBEDDED", "1")
    embedded = service.build_client()
    assert embedded.append("detection", {"x": 1}).seq == 0 and embedded.verify().ok
    embedded.close()
