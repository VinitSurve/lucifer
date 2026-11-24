import pytest
from pathlib import Path
from lucifer_agent.executor import ControlledExecutor, IsolatedExecutionProvider, SAFE_PROCESS_ENV
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

def test_python3_interpreter_strictly_blocked(tmp_path, monkeypatch):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # Attempt arbitrary python code execution on host - MUST BE BLOCKED
    monkeypatch.setattr(IsolatedExecutionProvider, "is_isolation_available", classmethod(lambda cls: False))
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

def test_npm_pnpm_pytest_uv_blocked_on_host(tmp_path, monkeypatch):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # All build tools, interpreters, and test runners must be blocked on host
    monkeypatch.setattr(IsolatedExecutionProvider, "is_isolation_available", classmethod(lambda cls: False))
    for tool, args in [("npm", ["test"]), ("pnpm", ["run", "build"]), ("pytest", ["-q"]), ("uv", ["run", "test"])]:
        res = executor.execute_command(tool, args, str(safe_dir))
        assert res["success"] is False
        assert "not permitted to execute on the host machine" in res["error"]

def test_git_fsmonitor_and_flags_neutralized(tmp_path):
    import subprocess
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    repo_dir = safe_dir / "test_repo"
    repo_dir.mkdir()

    # Initialize a git repo and configure core.fsmonitor to touch a canary
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)

    canary = repo_dir / "canary_fsmonitor.txt"
    fs_script = repo_dir / "fs.sh"
    fs_script.write_text(f"#!/bin/sh\ntouch '{canary}'\n", encoding="utf-8")
    fs_script.chmod(0o755)

    subprocess.run(["git", "config", "core.fsmonitor", str(fs_script)], cwd=repo_dir, check=True)

    executor = ControlledExecutor([str(safe_dir)])
    status_res = executor.read_git_status(str(repo_dir))
    assert status_res["success"] is True
    # The canary file MUST NOT have been created by fsmonitor!
    assert canary.exists() is False

    # Also test --output is blocked
    output_blocked = executor.execute_command("git", ["log", "--output=pwn.txt"], str(repo_dir))
    assert output_blocked["success"] is False
    assert "Dangerous git flag disallowed" in output_blocked["error"]

def test_sensitive_file_patterns_expanded(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # .env_production
    f1 = safe_dir / ".env_production"
    f1.write_text("DB_PASS=123", encoding="utf-8")
    assert executor.read_file(str(f1))["success"] is False

    # credentials.yaml
    f2 = safe_dir / "credentials.yaml"
    f2.write_text("key: secret", encoding="utf-8")
    assert executor.read_file(str(f2))["success"] is False

    # wrangler.toml
    f3 = safe_dir / "wrangler.toml"
    f3.write_text("token=secret", encoding="utf-8")
    assert executor.read_file(str(f3))["success"] is False

def test_manifest_inspection_safe(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    pkg_json = safe_dir / "package.json"
    pkg_json.write_text('{"name": "my-app", "version": "1.0.0", "scripts": {"test": "rm -rf /"}, "dependencies": {"express": "4.0"}}', encoding="utf-8")

    manifest = executor.inspect_project_manifest(str(pkg_json))
    assert manifest["success"] is True
    assert manifest["name"] == "my-app"
    assert "test" in manifest["scripts"]
    assert "express" in manifest["dependencies"]

def test_directory_listing_and_workspace_search(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    (safe_dir / "hello.py").write_text("print('hello world')", encoding="utf-8")
    (safe_dir / "secret.env").write_text("KEY=123", encoding="utf-8")

    # List directory
    listing = executor.list_directory(str(safe_dir))
    assert listing["success"] is True
    names = [e["name"] for e in listing["entries"]]
    assert "hello.py" in names

    # Search workspace
    search_res = executor.search_workspace(str(safe_dir), "hello")
    assert search_res["success"] is True
    assert len(search_res["results"]) > 0
    assert "hello world" in search_res["results"][0]["text"]

def test_adversarial_binary_substitution_blocked(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    canary = tmp_path / "outside_canary.txt"

    # 1. Create malicious executables named echo, ls, git in various locations
    locations = [
        tmp_path / "malicious_bin",
        safe_dir / "nested_bin",
        safe_dir
    ]
    for loc in locations:
        loc.mkdir(parents=True, exist_ok=True)
        for cmd_name in ["echo", "ls", "git"]:
            mal_bin = loc / cmd_name
            mal_bin.write_text(f"#!/bin/sh\ntouch '{canary}'\nexit 1\n", encoding="utf-8")
            mal_bin.chmod(0o755)

    # Test all variations of path invocation
    prohibited_invocations = [
        str(safe_dir / "echo"),
        str(safe_dir / "ls"),
        str(safe_dir / "git"),
        "./echo",
        "./ls",
        "./git",
        "../safe_projects/echo",
        str(tmp_path / "malicious_bin" / "echo"),
        str(tmp_path / "malicious_bin" / "ls"),
        str(tmp_path / "malicious_bin" / "git"),
        f"{safe_dir}/nested_bin/echo",
        "/bin/echo",
        "/bin/ls",
        "/usr/bin/git",
        "echo\x00extra",
        "echo/extra"
    ]

    for inv in prohibited_invocations:
        res = executor.execute_command(inv, ["hello"], str(safe_dir))
        assert res["success"] is False
        assert "Invalid command identifier" in res["error"] or "outside permitted" in res.get("error", "") or "not in the local agent" in res.get("error", "")
        assert canary.exists() is False, f"Malicious executable was invoked for: {inv}"

    # Verify that safe bare command execution continues to function properly
    safe_echo = executor.execute_command("echo", ["safe_call", "test"], str(safe_dir))
    assert safe_echo["success"] is True
    assert "safe_call test" in safe_echo["stdout"]
    assert canary.exists() is False

def test_adversarial_case_insensitive_sensitive_files(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    # Test case variations and modern credential file types
    sensitive_samples = [
        (".env", "SECRET=1"),
        (".ENV", "SECRET=2"),
        (".Env", "SECRET=3"),
        (".eNv", "SECRET=4"),
        (".env.local", "SECRET=5"),
        (".ENV.PRODUCTION", "SECRET=6"),
        (".envrc", "export SECRET=7"),
        ("credentials.json", '{"key": "secret"}'),
        ("CREDENTIALS.JSON", '{"key": "secret"}'),
        ("Credentials.Yaml", "key: secret"),
        (".git-credentials", "https://token@github.com"),
        (".GIT-CREDENTIALS", "https://token@github.com"),
        ("wrangler.toml", 'token="cf_secret"'),
        ("WRANGLER.TOML", 'token="cf_secret"'),
        ("Wrangler.Toml", 'token="cf_secret"'),
        (".npmrc", "//registry.npmjs.org/:_authToken=secret"),
        (".NPMRC", "//registry.npmjs.org/:_authToken=secret"),
        (".pypirc", "password = secret"),
        (".netrc", "password secret"),
        ("id_rsa", "PRIVATE KEY DATA"),
        ("ID_RSA", "PRIVATE KEY DATA"),
        ("id_ed25519", "PRIVATE KEY DATA"),
        ("server.key", "PRIVATE KEY DATA"),
        ("SERVER.KEY", "PRIVATE KEY DATA"),
        ("cert.pem", "CERT DATA"),
        ("CERT.PEM", "CERT DATA"),
        (".docker/config.json", '{"auths": {}}'),
        (".aws/credentials", "[default]\naws_secret_access_key=secret"),
        (".git/config", "[core]\nbare=false"),
        (".git/HEAD", "ref: refs/heads/main"),
        ("secrets/api_token.txt", "token=12345"),
        ("private_keys/deploy.key", "KEY DATA")
    ]

    for fname, content in sensitive_samples:
        file_path = safe_dir / fname
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")

        # Must be recognized as sensitive
        assert executor.is_sensitive_file(str(file_path)) is True, f"Failed sensitive check: {fname}"
        # Direct read must be blocked
        read_res = executor.read_file(str(file_path))
        assert read_res["success"] is False, f"Sensitive file read was not blocked: {fname}"
        assert "Access to sensitive file" in read_res["error"]

def test_adversarial_symlink_escape_and_traversal(tmp_path):
    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    outside_dir = tmp_path / "outside_world"
    outside_dir.mkdir()

    outside_secret = outside_dir / "target_secret.txt"
    outside_secret.write_text("SUPER_CONFIDENTIAL_DATA", encoding="utf-8")

    executor = ControlledExecutor([str(safe_dir)])

    # 1. Symlink inside safe_dir pointing to outside secret
    symlink_file = safe_dir / "symlink_to_secret.txt"
    symlink_file.symlink_to(outside_secret)

    res_symlink = executor.read_file(str(symlink_file))
    assert res_symlink["success"] is False
    assert "Access denied" in res_symlink["error"]

    # 2. Path traversal with ..
    res_traversal = executor.read_file(str(safe_dir / ".." / "outside_world" / "target_secret.txt"))
    assert res_traversal["success"] is False
    assert "Access denied" in res_traversal["error"]

    # 3. Path traversal in execute_command cwd
    res_cwd_traversal = executor.execute_command("echo", ["hello"], str(safe_dir / ".." / "outside_world"))
    assert res_cwd_traversal["success"] is False
    assert "outside permitted" in res_cwd_traversal["error"]

# =============================================================================
# PHASE 5.1.2: DOCKER ENDPOINT RESOLUTION & PID LIMIT REGRESSION TESTS
# =============================================================================

def test_docker_deterministic_endpoint_resolution(monkeypatch, tmp_path):
    """Verifies deterministic Docker endpoint resolution under SAFE_PROCESS_ENV."""
    import uuid
    import socket
    fake_sock = Path(f"/tmp/d_{uuid.uuid4().hex[:6]}.sock")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(fake_sock))
    try:
        monkeypatch.setenv("DOCKER_HOST", f"unix://{fake_sock}")
        endpoint = IsolatedExecutionProvider.resolve_docker_endpoint()
        assert endpoint == f"unix://{fake_sock.resolve()}"

        safe_env = IsolatedExecutionProvider.get_safe_process_env()
        assert safe_env["DOCKER_HOST"] == f"unix://{fake_sock.resolve()}"
        assert safe_env["HOME"] == "/tmp"  # Sanitized HOME preserved
        assert "LANG" in safe_env
    finally:
        s.close()
        if fake_sock.exists():
            fake_sock.unlink()

    fake_file = tmp_path / "not_a_socket.txt"
    fake_file.write_text("dummy", encoding="utf-8")
    monkeypatch.setenv("DOCKER_HOST", f"unix://{fake_file}")
    ep_non_sock = IsolatedExecutionProvider.resolve_docker_endpoint()
    assert ep_non_sock != f"unix://{fake_file}"

    monkeypatch.setenv("DOCKER_HOST", "tcp://evil.com:1234; rm -rf /")
    ep_invalid = IsolatedExecutionProvider.resolve_docker_endpoint()
    assert ep_invalid != "tcp://evil.com:1234; rm -rf /"

def test_docker_pids_limit_in_command(tmp_path, monkeypatch):
    """Verifies --pids-limit 128 is included in generated docker command."""
    import subprocess
    executed_cmds = []

    def mock_run(cmd, **kwargs):
        executed_cmds.append(cmd)
        class Res:
            returncode = 0
            stdout = "success"
            stderr = ""
        return Res()

    monkeypatch.setattr(IsolatedExecutionProvider, "is_isolation_available", classmethod(lambda cls: True))
    monkeypatch.setattr(subprocess, "run", mock_run)

    safe_dir = tmp_path / "safe_projects"
    safe_dir.mkdir()
    executor = ControlledExecutor([str(safe_dir)])

    executor.execute_command("python", ["-c", "print(1)"], str(safe_dir))
    assert len(executed_cmds) > 0
    cmd = executed_cmds[0]
    assert "--pids-limit" in cmd
    idx = cmd.index("--pids-limit")
    assert cmd[idx + 1] == "128"
