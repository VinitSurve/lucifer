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

def test_python3_interpreter_strictly_blocked(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # Attempt arbitrary python code execution - MUST BE BLOCKED
    blocked = executor.execute_command("python3", ["-c", "import sys; print('pwned')"], str(safe_dir))
    assert blocked["success"] is False
    assert "arbitrary interpreters are blocked" in blocked["error"]

def test_shell_metacharacters_and_traversal_blocked(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # Shell pipe attempt
    pipe_attempt = executor.execute_command("echo", ["hello", "|", "whoami"], str(safe_dir))
    assert pipe_attempt["success"] is False
    assert "Disallowed character in argument" in pipe_attempt["error"]

    # Semicolon command chaining attempt
    semi_attempt = executor.execute_command("echo", ["hello;", "id"], str(safe_dir))
    assert semi_attempt["success"] is False
    assert "Disallowed character in argument" in semi_attempt["error"]

    # Path traversal attempt in arguments
    traversal_attempt = executor.execute_command("git", ["diff", "../../etc/passwd"], str(safe_dir))
    assert traversal_attempt["success"] is False
    assert "Path traversal ('..') disallowed" in traversal_attempt["error"]

def test_git_subcommand_allowlist(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # Disallowed git push / clone / config
    push_blocked = executor.execute_command("git", ["push", "origin", "main"], str(safe_dir))
    assert push_blocked["success"] is False
    assert "not permitted" in push_blocked["error"]

    config_blocked = executor.execute_command("git", ["config", "core.pager", "cat"], str(safe_dir))
    assert config_blocked["success"] is False

def test_sensitive_file_read_blocked(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # Create fake .env and private key inside safe directory
    env_file = safe_dir / ".env"
    env_file.write_text("SECRET_KEY=12345", encoding="utf-8")

    key_file = safe_dir / "id_rsa"
    key_file.write_text("PRIVATE KEY DATA", encoding="utf-8")

    res_env = executor.read_file(str(env_file))
    assert res_env["success"] is False
    assert "Access to sensitive file" in res_env["error"]

    res_key = executor.read_file(str(key_file))
    assert res_key["success"] is False
    assert "Access to sensitive file" in res_key["error"]
