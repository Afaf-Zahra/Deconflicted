import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from deconflicted.ledger import load_policy

ROOT = Path(__file__).parents[2]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]
NODES = ["ledger-a", "ledger-b", "ledger-c"]


def test_services_and_networks():
    assert set(SERVICES) == {*NODES, "api", "web", "replay"}
    assert COMPOSE["networks"]["internal"]["internal"] is True, "the internal network has no route out"
    assert not COMPOSE["networks"]["frontend"].get("internal")
    for name in NODES:
        assert SERVICES[name]["networks"] == ["internal"], f"{name} must only be on the internal network"
        assert "ports" not in SERVICES[name], f"{name} must not publish a port"
    assert SERVICES["api"]["networks"] == ["internal", "frontend"] and SERVICES["web"]["networks"] == ["internal", "frontend"]
    assert SERVICES["replay"]["networks"] == ["internal"]


def test_published_ports_and_isolation_settings():
    assert SERVICES["api"]["ports"] == ["8000:8000"] and SERVICES["web"]["ports"] == ["8080:8080"]
    for name, service in SERVICES.items():
        assert service.get("network_mode") != "host", name
        assert not service.get("privileged"), name


def test_health_checks_and_start_order():
    for name in (*NODES, "api", "web"):
        assert "healthcheck" in SERVICES[name], name
    assert SERVICES["api"]["depends_on"] == {n: {"condition": "service_healthy"} for n in NODES}
    assert SERVICES["web"]["depends_on"] == {"api": {"condition": "service_healthy"}}
    assert SERVICES["replay"]["profiles"] == ["demo"]
    assert SERVICES["replay"]["depends_on"] == {"api": {"condition": "service_healthy"}}


def test_nodes_match_policy():
    policy = load_policy(ROOT / "config" / "policy.yaml")
    ids = [SERVICES[n]["command"][SERVICES[n]["command"].index("--id") + 1] for n in NODES]
    assert ids == list(policy.nodes)
    spec = SERVICES["api"]["environment"]["DECONFLICTED_LEDGER_NODES"]
    assert [pair.split("=")[0] for pair in spec.split(",")] == list(policy.nodes)
    assert len({SERVICES[n]["volumes"][0] for n in NODES}) == 3, "each node keeps its own data"


def test_api_image_installs_the_two_requirement_files_separately():
    text = (ROOT / "docker" / "Dockerfile.api").read_text()
    runs = [line for line in text.splitlines() if "pip install" in line and line.startswith("RUN")]
    assert len(runs) == 2 and "requirements.txt" in runs[0] and "requirements-ml.txt" in runs[1]
    assert 'ARG WITH_ML=1' in text and 'if [ "$WITH_ML" = "1" ]' in runs[1], "PyTorch can be left out of a dev build"
    assert (ROOT / "requirements-ml.txt").read_text().startswith("--index-url")
    assert "python:3.11" in text
    assert "node:22" in (ROOT / "docker" / "Dockerfile.web").read_text()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")
@pytest.mark.parametrize("script", ["offline_check.sh", "export_images.sh", "load_images.sh", "reset_demo.sh"])
def test_scripts_have_valid_syntax(script):
    result = subprocess.run(["bash", "-n", f"scripts/{script}"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_offline_check_covers_every_step_and_never_builds():
    text = (ROOT / "scripts" / "offline_check.sh").read_text()
    for step in ("host is offline", "stack starts from built images", "api and ledger nodes are healthy",
                 "replay of the demo scenario", "ledger verifies", "three ledger nodes are up",
                 "audit export downloads", "audit export verifies offline"):
        assert f'step "{step}' in text, step
    assert "--no-build" in text and "up --build" not in text
    assert "ALL STEPS PASSED" in text and "exit" in text


def test_offline_check_starts_the_stack_without_the_replay_profile():
    text = (ROOT / "scripts" / "offline_check.sh").read_text()
    start = next(line for line in text.splitlines() if line.startswith('step "stack starts'))
    assert "--profile" not in start, "the replay service must not start with the stack, or the scenario is replayed twice"
    replay = next(line for line in text.splitlines() if line.startswith('step "replay of the demo'))
    assert "--profile demo" in replay and " run " in replay


def test_reset_script_removes_every_volume_together():
    text = (ROOT / "scripts" / "reset_demo.sh").read_text()
    assert "down -v" in text and "--profile demo" in text
