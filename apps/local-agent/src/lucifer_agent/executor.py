import os
import re
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

# Strictly controlled environment for spawned child processes
# Strips all API keys, secrets, tokens, and arbitrary Git environment variables
SAFE_PROCESS_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
    "HOME": "/tmp",
    "LANG": "en_US.UTF-8",
    "LC_ALL": "en_US.UTF-8",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0"
}

class IsolatedExecutionProvider:
    """Manages isolated code execution in ephemeral container environments.
    Strictly forbids running arbitrary code on the host machine.
    If Docker or container isolation is unavailable, code execution remains disabled.
    """

    @staticmethod
    def is_isolation_available() -> bool:
        """Detects whether Docker container isolation is available and responsive."""
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return False
        try:
            # Check if docker daemon is responding with 2-second timeout
            res = subprocess.run(
                [docker_bin, "info"],
                capture_output=True,
                text=True,
                timeout=2,
                env=SAFE_PROCESS_ENV
            )
            return res.returncode == 0
        except Exception:
            return False

    @classmethod
    def execute_in_container(cls, image: str, command: List[str], workspace_mount: str, timeout: int = 30) -> Dict[str, Any]:
        """Runs command inside a restricted disposable container."""
        if not cls.is_isolation_available():
            return {
                "success": False,
                "error": "Isolated container environment (Docker) is unavailable. Code execution on host is strictly disabled."
            }

        docker_bin = shutil.which("docker") or "docker"
        docker_cmd = [
            docker_bin, "run", "--rm",
            "--user", "1000:1000",            # Non-root user
            "--network", "none",              # No network by default
            "--cap-drop", "ALL",              # Drop all Linux capabilities
            "--security-opt", "no-new-privileges",
            "--memory", "512m",               # 512MB RAM limit
            "--cpus", "1.0",                  # 1 CPU core limit
            "-v", f"{workspace_mount}:/workspace:ro", # Read-only workspace mount
            "-w", "/workspace",
            image
        ] + command

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=SAFE_PROCESS_ENV
            )
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": proc.stdout[:10000],
                "stderr": proc.stderr[:5000]
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Execution timed out ({timeout}s limit)"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class ControlledExecutor:
    """Capability-based executor for local agent operations.
    Exposes narrowly scoped, read-only inspection operations.
    Explicitly removes npm, pnpm, pytest, uv, arbitrary interpreters, and shell execution on host.
    """

    # Only safe inspection utilities allowed on host (NO interpreters, NO package managers, NO test runners)
    ALLOWED_COMMANDS = {
        "git",
        "echo",
        "ls"
    }

    # Block any shell metacharacters or dangerous control codes in arguments
    METACHO_REGEX = re.compile(r"[;&|`$\n\r><\(\)\{\}\[\]!]")

    # Sensitive files that must NEVER be read or exposed
    SENSITIVE_FILE_PATTERNS = [
        re.compile(r"(^|/)\.env(_.*|\..*)?$"),                 # .env, .env_production, .env.local, .env.backup
        re.compile(r"(^|/)credentials(\..+)?$"),              # credentials, credentials.yaml, credentials.json
        re.compile(r"(^|/)wrangler\.toml$"),                  # Cloudflare worker configs
        re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)"),      # SSH private keys
        re.compile(r"\.(pem|key|p12|pfx|pkcs12)$"),           # Certificates and keys
        re.compile(r"(^|/)(secrets|\.netrc|\.npmrc|\.aws/credentials)"),
        re.compile(r"(^|/)\.git/(config|hooks)")              # Git internal configs and hooks
    ]

    def __init__(self, allowed_directories: List[str]):
        self.allowed_directories = [Path(d).resolve() for d in allowed_directories]

    def is_path_safe(self, target_path: str) -> bool:
        """Ensures path stays strictly within allowlisted directories and prevents symlink escape."""
        try:
            p = Path(target_path)
            # Resolve symlinks to target destination
            resolved = p.resolve(strict=False)
            return any(resolved == allowed or allowed in resolved.parents for allowed in self.allowed_directories)
        except Exception:
            return False

    def is_sensitive_file(self, target_path: str) -> bool:
        """Checks if a file matches known sensitive credential patterns."""
        path_str = str(Path(target_path).resolve())
        return any(pattern.search(path_str) for pattern in self.SENSITIVE_FILE_PATTERNS)

    # =========================================================================
    # CAPABILITY-BASED OPERATIONS
    # =========================================================================

    def read_file(self, file_path: str, max_bytes: int = 512_000) -> Dict[str, Any]:
        """Reads a file safely if within allowed projects and not sensitive."""
        if not self.is_path_safe(file_path):
            return {"success": False, "error": f"Access denied to file: {file_path}"}

        p = Path(file_path).resolve()
        if not p.is_file():
            return {"success": False, "error": f"File does not exist: {file_path}"}

        if self.is_sensitive_file(str(p)):
            return {"success": False, "error": f"Access to sensitive file '{p.name}' is strictly blocked."}

        if p.stat().st_size > max_bytes:
            return {"success": False, "error": f"File size exceeds {max_bytes // 1024}KB limit"}

        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            return {"success": True, "content": content}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_directory(self, dir_path: str, max_entries: int = 200) -> Dict[str, Any]:
        """Lists directory entries safely without executing directory contents."""
        if not self.is_path_safe(dir_path):
            return {"success": False, "error": f"Access denied to directory: {dir_path}"}

        p = Path(dir_path).resolve()
        if not p.is_dir():
            return {"success": False, "error": f"Path is not a directory: {dir_path}"}

        try:
            entries = []
            for item in sorted(p.iterdir()):
                if len(entries) >= max_entries:
                    break
                # Do not display contents of sensitive files
                is_sensitive = self.is_sensitive_file(str(item))
                entries.append({
                    "name": item.name,
                    "is_dir": item.is_dir(),
                    "size": item.stat().st_size if item.is_file() else 0,
                    "sensitive": is_sensitive
                })
            return {"success": True, "entries": entries}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def search_workspace(self, dir_path: str, query: str, max_results: int = 50) -> Dict[str, Any]:
        """Searches text across files in a workspace without shell grep."""
        if not self.is_path_safe(dir_path):
            return {"success": False, "error": f"Access denied to directory: {dir_path}"}

        if not query or len(query.strip()) < 2:
            return {"success": False, "error": "Query must be at least 2 characters"}

        p = Path(dir_path).resolve()
        results = []
        try:
            for root, dirs, files in os.walk(p):
                # Skip git directories and hidden dirs
                dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
                for f in files:
                    if len(results) >= max_results:
                        break
                    file_path = Path(root) / f
                    if self.is_sensitive_file(str(file_path)):
                        continue
                    if file_path.stat().st_size > 256_000: # Skip large files
                        continue
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        for line_num, line in enumerate(content.splitlines(), start=1):
                            if query in line:
                                results.append({
                                    "file": str(file_path.relative_to(p)),
                                    "line": line_num,
                                    "text": line.strip()[:200]
                                })
                                if len(results) >= max_results:
                                    break
                    except Exception:
                        continue
            return {"success": True, "results": results}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def inspect_project_manifest(self, manifest_path: str) -> Dict[str, Any]:
        """Safely parses package.json or pyproject.toml as structured data without executing scripts."""
        if not self.is_path_safe(manifest_path):
            return {"success": False, "error": f"Access denied to manifest: {manifest_path}"}

        p = Path(manifest_path).resolve()
        if not p.is_file():
            return {"success": False, "error": f"Manifest does not exist: {manifest_path}"}

        if p.name == "package.json":
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return {
                    "success": True,
                    "manifest_type": "npm",
                    "name": data.get("name"),
                    "version": data.get("version"),
                    "scripts": list((data.get("scripts") or {}).keys()),
                    "dependencies": list((data.get("dependencies") or {}).keys()),
                    "devDependencies": list((data.get("devDependencies") or {}).keys())
                }
            except Exception as e:
                return {"success": False, "error": f"Failed to parse package.json: {e}"}

        elif p.name == "pyproject.toml":
            try:
                # Basic line-based extraction without executing TOML or loading modules
                content = p.read_text(encoding="utf-8")
                return {
                    "success": True,
                    "manifest_type": "pyproject",
                    "lines": len(content.splitlines()),
                    "size": len(content)
                }
            except Exception as e:
                return {"success": False, "error": f"Failed to read pyproject.toml: {e}"}

        return {"success": False, "error": f"Unsupported manifest type: {p.name}"}

    # =========================================================================
    # SAFE GIT INSPECTION (Hardened against repository poisoning)
    # =========================================================================

    def _execute_safe_git(self, subcmd_args: List[str], repo_path: str) -> Dict[str, Any]:
        """Executes a Git read operation with strict safety overrides to prevent hook or driver execution."""
        if not self.is_path_safe(repo_path):
            return {"success": False, "error": f"Repository path outside allowed directories: {repo_path}"}

        git_bin = shutil.which("git") or "/usr/bin/git"

        # Mandatory overrides to neutralize malicious .git/config, hooks, pagers, and fsmonitors
        safe_git_flags = [
            "-c", "core.fsmonitor=false",
            "-c", "core.pager=cat",
            "-c", "diff.autorefreshindex=false",
            "-c", "core.hooksPath=/dev/null",
            "-c", "diff.external=/dev/null",
            "--no-pager"
        ]

        # Filter out disallowed flags
        for arg in subcmd_args:
            if self.METACHO_REGEX.search(arg):
                return {"success": False, "error": f"Disallowed character in git argument: '{arg}'"}
            if ".." in arg:
                return {"success": False, "error": f"Path traversal ('..') disallowed in git argument: '{arg}'"}
            if arg.startswith("--output") or arg.startswith("-o") or arg.startswith("--ext-diff") or arg.startswith("--exec-path"):
                return {"success": False, "error": f"Dangerous git flag disallowed: '{arg}'"}

        cmd = [git_bin] + safe_git_flags + subcmd_args
        try:
            proc = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=15,
                env=SAFE_PROCESS_ENV, # Isolated environment, no parent secrets
                shell=False
            )
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": proc.stdout[:10000],
                "stderr": proc.stderr[:5000]
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Git operation timed out (15s limit)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def read_git_status(self, repo_path: str) -> Dict[str, Any]:
        """Reads safe Git status with hooks and fsmonitor completely disabled."""
        return self._execute_safe_git(["status", "--porcelain", "--no-renames"], repo_path)

    def read_git_diff(self, repo_path: str, cached: bool = False) -> Dict[str, Any]:
        """Reads safe Git diff with external diff drivers disabled."""
        args = ["diff", "--no-ext-diff", "--no-color"]
        if cached:
            args.append("--cached")
        return self._execute_safe_git(args, repo_path)

    def read_git_log(self, repo_path: str, max_commits: int = 10) -> Dict[str, Any]:
        """Reads safe Git log with pagers disabled."""
        n = min(max(1, max_commits), 50)
        return self._execute_safe_git(["log", f"-n{n}", "--oneline"], repo_path)

    # =========================================================================
    # COMMAND EXECUTION ROUTER (Host vs Isolated)
    # =========================================================================

    def execute_command(self, command: str, args: List[str], cwd: str) -> Dict[str, Any]:
        """Executes a permitted inspection command or routes code execution to isolated container."""
        cmd_name = Path(command).name

        # 1. Explicitly rejected commands that execute arbitrary code/scripts on host
        BLOCKED_HOST_COMMANDS = {
            "python", "python3", "node", "bash", "sh", "zsh",
            "npm", "pnpm", "yarn", "pytest", "uv"
        }

        if cmd_name in BLOCKED_HOST_COMMANDS:
            # Check if isolated container execution is available
            if IsolatedExecutionProvider.is_isolation_available():
                # Route to isolated disposable container
                return IsolatedExecutionProvider.execute_in_container(
                    image="python:3.12-slim" if "py" in cmd_name else "node:20-slim",
                    command=[cmd_name] + args,
                    workspace_mount=cwd
                )
            return {
                "success": False,
                "error": f"Command '{cmd_name}' is not permitted to execute on the host machine. Host execution of build tools, test runners, and arbitrary interpreters are blocked by security policy."
            }

        if cmd_name not in self.ALLOWED_COMMANDS:
            return {
                "success": False,
                "error": f"Command '{cmd_name}' is not in the local agent command allowlist."
            }

        if not self.is_path_safe(cwd):
            return {
                "success": False,
                "error": f"Working directory '{cwd}' is outside permitted directories."
            }

        # 2. Git is handled via safe inspection pipeline
        if cmd_name == "git":
            if not args:
                return {"success": False, "error": "Git command requires a subcommand."}
            subcmd = args[0].lower()
            allowed_subcmds = {"status", "diff", "log", "branch", "show"}
            if subcmd not in allowed_subcmds:
                return {"success": False, "error": f"Git subcommand '{subcmd}' is not permitted. Only {allowed_subcmds} are allowed."}
            return self._execute_safe_git(args, cwd)

        # 3. Echo / Ls safe handling
        for arg in args:
            if self.METACHO_REGEX.search(arg):
                return {"success": False, "error": f"Disallowed character in argument: '{arg}'"}
            if ".." in arg:
                return {"success": False, "error": f"Path traversal in argument: '{arg}'"}

        if cmd_name == "ls":
            allowed_ls_flags = {"-l", "-a", "-la", "-lh", "-lah", "-1"}
            for arg in args:
                if arg.startswith("-") and arg not in allowed_ls_flags:
                    return {"success": False, "error": f"Disallowed ls flag: '{arg}'"}

        cmd_list = [command] + args
        try:
            proc = subprocess.run(
                cmd_list,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=15,
                env=SAFE_PROCESS_ENV, # Isolated environment
                shell=False
            )
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": proc.stdout[:10000],
                "stderr": proc.stderr[:5000]
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Execution timed out (15s limit)"}
        except Exception as e:
            return {"success": False, "error": str(e)}
