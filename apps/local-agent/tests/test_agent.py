import pytest
from pathlib import Path
from lucifer_agent.executor import ControlledExecutor
from lucifer_agent.sysinfo import get_system_metrics
from lucifer_agent.ollama_client import OllamaClient

def test_system_metrics():
    metrics = get_system_metrics()
    assert "os" in metrics
    assert "arch" in metrics
    assert "ram_total_gb" in metrics
    assert metrics["disk_free_gb"] > 0

def test_controlled_executor_path_safety(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # Path inside safe dir
    file_inside = safe_dir / "test.txt"
    file_inside.write_text("hello lucifer", encoding="utf-8")
    assert executor.is_path_safe(str(file_inside)) is True

    # Path outside safe dir (e.g. /etc/passwd or tmp_path)
    assert executor.is_path_safe("/etc/passwd") is False
    assert executor.is_path_safe(str(safe_dir / ".." / "outside.txt")) is False

def test_controlled_executor_read_file(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    test_file = safe_dir / "data.json"
    test_file.write_text('{"status": "ok"}', encoding="utf-8")

    res = executor.read_file(str(test_file))
    assert res["success"] is True
    assert res["content"] == '{"status": "ok"}'

    # Denied reading file outside
    denied = executor.read_file("/etc/hosts")
    assert denied["success"] is False
    assert "Access denied" in denied["error"]

def test_controlled_executor_command_allowlist(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # Allowed command: echo
    res = executor.execute_command("echo", ["hello"], str(safe_dir))
    assert res["success"] is True
    assert "hello" in res["stdout"]

    # Disallowed dangerous command: rm or bash
    blocked = executor.execute_command("rm", ["-rf", "something"], str(safe_dir))
    assert blocked["success"] is False
    assert "not in the local agent command allowlist" in blocked["error"]
