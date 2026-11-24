import os
import re
import json
import stat
import uuid
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

    @classmethod
    def _is_trusted_socket_path(cls, path: Path) -> bool:
        """Validates that a Unix domain socket path belongs to a trusted, secure location.
        Approved locations:
        1. System Docker socket: /var/run/docker.sock or /run/docker.sock.
        2. Colima user socket: ~/.colima/<profile>/*.sock.
        3. Docker Desktop user socket: ~/.docker/run/*.sock.
        Rejects arbitrary user paths, world-writable directories, symlink escapes, or TCP endpoints.
        """
        try:
            st = path.stat()
            if not stat.S_ISSOCK(st.st_mode):
                return False

            resolved = path.resolve()
            rst = resolved.stat()
            if not stat.S_ISSOCK(rst.st_mode):
                return False

            # Verify ownership: must be owned by root (UID 0) or current user
            current_uid = os.getuid()
            if rst.st_uid not in (0, current_uid):
                return False

            # Check approved locations
            system_sockets = {
                Path("/var/run/docker.sock").resolve(),
                Path("/run/docker.sock").resolve()
            }
            if resolved in system_sockets:
                return True

            home_resolved = Path.home().resolve()
            colima_root = home_resolved / ".colima"
            docker_run_root = home_resolved / ".docker" / "run"

            if colima_root in resolved.parents and resolved.name.endswith(".sock"):
                return True

            if docker_run_root in resolved.parents and resolved.name.endswith(".sock"):
                return True

            return False
        except Exception:
            return False

    @classmethod
    def resolve_docker_endpoint(cls) -> Optional[str]:
        """Resolves trusted Docker endpoint without relying on arbitrary user HOME environment.
        Strict policy:
        1. TCP endpoints are strictly rejected by security policy (DEF-01).
        2. DOCKER_HOST unix:// sockets must satisfy _is_trusted_socket_path (DEF-02).
        3. Probes standard candidate sockets in order of precedence:
           - ~/.colima/default/docker.sock
           - /var/run/docker.sock
           - /run/docker.sock
           - ~/.docker/run/docker.sock
        Returns validated endpoint string (e.g. 'unix:///path/to/docker.sock') or None if unavailable.
        """
        raw_env_host = os.environ.get("DOCKER_HOST", "").strip()
        if raw_env_host:
            # Strictly reject plaintext/remote TCP endpoints by default policy (DEF-01)
            if raw_env_host.startswith("tcp://") or raw_env_host.startswith("http://") or raw_env_host.startswith("https://"):
                return None

            if raw_env_host.startswith("unix://"):
                sock_path = Path(raw_env_host[len("unix://"):])
                if cls._is_trusted_socket_path(sock_path):
                    return f"unix://{sock_path.resolve()}"
                # If an untrusted unix socket path is specified, fail closed
                return None

        # Probe trusted candidate socket paths in order
        candidates = [
            Path.home() / ".colima" / "default" / "docker.sock",
            Path("/var/run/docker.sock"),
            Path("/run/docker.sock"),
            Path.home() / ".docker" / "run" / "docker.sock"
        ]
        for candidate in candidates:
            if cls._is_trusted_socket_path(candidate):
                return f"unix://{candidate.resolve()}"

        return None

    @classmethod
    def get_safe_process_env(cls) -> Dict[str, str]:
        """Returns strictly sanitized environment with trusted DOCKER_HOST if available."""
        env = dict(SAFE_PROCESS_ENV)
        endpoint = cls.resolve_docker_endpoint()
        if endpoint:
            env["DOCKER_HOST"] = endpoint
        return env

    @classmethod
    def _force_cleanup_container(cls, docker_bin: str, container_name: str, env: Dict[str, str]) -> Dict[str, Any]:
        """Forcibly terminates and removes a container on timeout or failure.
        Confirms that the container is no longer running on the daemon.
        """
        try:
            rm_proc = subprocess.run(
                [docker_bin, "rm", "-f", container_name],
                capture_output=True,
                text=True,
                timeout=5,
                env=env
            )
            # Verify container is genuinely removed
            ps_proc = subprocess.run(
                [docker_bin, "ps", "-a", "--filter", f"name={container_name}", "-q"],
                capture_output=True,
                text=True,
                timeout=2,
                env=env
            )
            is_gone = not bool(ps_proc.stdout.strip())
            return {
                "success": is_gone,
                "returncode": rm_proc.returncode,
                "confirmed_removed": is_gone,
                "stderr": rm_proc.stderr[:500] if rm_proc.returncode != 0 else ""
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Cleanup failed: {e}",
                "confirmed_removed": False
            }

    @classmethod
    def is_isolation_available(cls) -> bool:
        """Detects whether Docker container isolation is available and responsive."""
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return False
        try:
            env = cls.get_safe_process_env()
            # Check if docker daemon is responding with 2-second timeout
            res = subprocess.run(
                [docker_bin, "info"],
                capture_output=True,
                text=True,
                timeout=2,
                env=env
            )
            return res.returncode == 0
        except Exception:
            return False

    @classmethod
    def execute_in_container(
        cls,
        image: str,
        command: List[str],
        workspace_mount: str,
        timeout: int = 30,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Runs command inside a restricted disposable container with guaranteed timeout cleanup."""
        if not cls.is_isolation_available():
            return {
                "success": False,
                "error": "Isolated container environment (Docker) is unavailable. Code execution on host is strictly disabled."
            }

        docker_bin = shutil.which("docker") or "docker"
        env = cls.get_safe_process_env()

        # Deterministic unique container name supporting safe concurrency
        unique_suffix = uuid.uuid4().hex[:12]
        if task_id:
            safe_task_id = re.sub(r"[^a-zA-Z0-9_-]", "", task_id)[:16]
            container_name = f"lucifer-exec-{safe_task_id}-{unique_suffix}"
        else:
            container_name = f"lucifer-exec-{unique_suffix}"

        docker_cmd = [
            docker_bin, "run",
            "--name", container_name,
            "--rm",
            "--user", "1000:1000",                    # Non-root user
            "--network", "none",                      # Complete network isolation
            "--cap-drop", "ALL",                      # Drop all Linux capabilities
            "--security-opt", "no-new-privileges",    # Prevent privilege escalation
            "--memory", "512m",                       # 512MB RAM cap
            "--cpus", "1.0",                          # 1 CPU core quota
            "--pids-limit", "128",                    # Explicit PID limit to prevent fork bombs
            "-v", f"{workspace_mount}:/workspace:ro", # Read-only workspace mount
            "-w", "/workspace",                       # Workdir inside container
            image
        ] + command

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": proc.stdout[:10000],
                "stderr": proc.stderr[:5000],
                "container_name": container_name
            }
        except subprocess.TimeoutExpired:
            # Forced cleanup: actively stop and remove the specific task container
            cleanup_res = cls._force_cleanup_container(docker_bin, container_name, env)
            return {
                "success": False,
                "error": f"Execution timed out ({timeout}s limit)",
                "timeout": True,
                "container_name": container_name,
                "cleanup": cleanup_res
            }
        except Exception as e:
            cls._force_cleanup_container(docker_bin, container_name, env)
            return {
                "success": False,
                "error": str(e),
                "container_name": container_name
            }


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

    # Sensitive files that must NEVER be read or exposed (case-insensitive across macOS/Linux)
    SENSITIVE_FILE_PATTERNS = [
        # Environment files (.env, .env.local, .env_production, .envrc, etc.)
        re.compile(r"(^|/)\.env(_.*|\..*)?$", re.IGNORECASE),
        re.compile(r"(^|/)\.envrc$", re.IGNORECASE),
        # Credential files
        re.compile(r"(^|/)credentials(\..+)?$", re.IGNORECASE),
        re.compile(r"(^|/)\.git-credentials$", re.IGNORECASE),
        re.compile(r"(^|/)\.netrc$", re.IGNORECASE),
        re.compile(r"(^|/)\.npmrc$", re.IGNORECASE),
        re.compile(r"(^|/)\.pypirc$", re.IGNORECASE),
        # Cloud and tool configs
        re.compile(r"(^|/)wrangler\.toml$", re.IGNORECASE),
        re.compile(r"(^|/)\.docker/config\.json$", re.IGNORECASE),
        re.compile(r"(^|/)\.(aws|gcloud|azure)(/|$)", re.IGNORECASE),
        # SSH and cryptographic keys
        re.compile(r"(^|/)\.ssh(/|$)", re.IGNORECASE),
        re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\..*)?$", re.IGNORECASE),
        re.compile(r"(^|/)(authorized_keys|known_hosts)$", re.IGNORECASE),
        re.compile(r"\.(pem|key|p12|pfx|pkcs12|keystore)$", re.IGNORECASE),
        # Secrets directories & Git metadata
        re.compile(r"(^|/)\.?(secrets|private_keys)(/|$)", re.IGNORECASE),
        re.compile(r"(^|/)\.git/(config|hooks|HEAD|index|credentials)", re.IGNORECASE)
    ]

    def __init__(self, allowed_directories: List[str]):
        self.allowed_directories = [Path(d).resolve() for d in allowed_directories]

    def is_path_safe(self, target_path: str) -> bool:
        """Ensures path stays strictly within allowlisted directories and prevents traversal or symlink escape."""
        if not target_path or not isinstance(target_path, str):
            return False
        # Reject raw traversal markers before resolution
        raw_parts = re.split(r"[/\\]+", target_path)
        if ".." in raw_parts:
            return False
        try:
            p = Path(target_path)
            # Resolve symlinks to target canonical destination
            resolved = p.resolve(strict=False)
            resolved_lower = str(resolved).lower()
            return any(
                str(allowed).lower() == resolved_lower or str(allowed).lower() in [str(parent).lower() for parent in resolved.parents]
                for allowed in self.allowed_directories
            )
        except Exception:
            return False

    def is_sensitive_file(self, target_path: str) -> bool:
        """Checks if a file matches known sensitive credential patterns using case-insensitive canonical evaluation."""
        if not target_path:
            return False
        try:
            p = Path(target_path)
            posix_path = p.as_posix()
            resolved_posix = p.resolve(strict=False).as_posix()
            # Normalize macOS system /private/var and /private/tmp prefix to avoid false positives on OS temp directories
            if resolved_posix.startswith("/private/var/") or resolved_posix.startswith("/private/tmp/"):
                resolved_posix = resolved_posix[len("/private"):]

            name = p.name
            # Check pattern matches against path, canonical path, and basename
            for pattern in self.SENSITIVE_FILE_PATTERNS:
                if pattern.search(posix_path) or pattern.search(resolved_posix) or pattern.search(name):
                    return True
            return False
        except Exception:
            return True # Fail closed on error

    # =========================================================================
    # CAPABILITY-BASED OPERATIONS
    # =========================================================================

    def read_file(self, file_path: str, max_bytes: int = 512_000) -> Dict[str, Any]:
        """Reads a file safely if within allowed projects and not sensitive.
        Uses descriptor-level inspection (fstat) to prevent TOCTOU race conditions.
        """
        if not self.is_path_safe(file_path):
            return {"success": False, "error": f"Access denied to file: {file_path}"}

        # Check sensitivity against both requested path and canonical resolved path
        if self.is_sensitive_file(file_path):
            return {"success": False, "error": f"Access to sensitive file '{Path(file_path).name}' is strictly blocked."}

        p = Path(file_path).resolve()
        if not p.is_file():
            return {"success": False, "error": f"File does not exist: {file_path}"}

        if self.is_sensitive_file(str(p)):
            return {"success": False, "error": f"Access to sensitive file '{p.name}' is strictly blocked."}

        # Open file descriptor for TOCTOU-safe inspection and read
        try:
            fd = os.open(str(p), os.O_RDONLY)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    return {"success": False, "error": f"Path is not a regular file: {file_path}"}
                if st.st_size > max_bytes:
                    return {"success": False, "error": f"File size exceeds {max_bytes // 1024}KB limit"}

                with open(fd, "r", encoding="utf-8", errors="replace", closefd=False) as f:
                    content = f.read(max_bytes + 1)
                    if len(content.encode("utf-8")) > max_bytes:
                        return {"success": False, "error": f"File size exceeds {max_bytes // 1024}KB limit"}
                    return {"success": True, "content": content}
            finally:
                os.close(fd)
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

    @staticmethod
    def _resolve_system_git() -> Optional[str]:
        """Resolves system git binary from trusted absolute system paths only."""
        trusted_paths = ["/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git"]
        for p in trusted_paths:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        which_git = shutil.which("git")
        if which_git and os.path.isabs(which_git) and os.path.isfile(which_git) and os.access(which_git, os.X_OK):
            return which_git
        return None

    def _execute_safe_git(self, subcmd_args: List[str], repo_path: str) -> Dict[str, Any]:
        """Executes a Git read operation with strict safety overrides to prevent hook or driver execution."""
        if not self.is_path_safe(repo_path):
            return {"success": False, "error": f"Repository path outside allowed directories: {repo_path}"}

        git_bin = self._resolve_system_git()
        if not git_bin:
            return {"success": False, "error": "System Git binary not found in trusted system directories."}

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
            if (arg.startswith("--output") or arg.startswith("-o") or arg.startswith("--ext-diff")
                    or arg.startswith("--exec-path") or arg.startswith("--work-tree") or arg.startswith("--git-dir")
                    or arg.startswith("--config") or arg == "-c" or arg.startswith("--upload-pack")
                    or arg.startswith("--receive-pack")):
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

    def execute_command(self, command: str, args: List[str], cwd: str, task_id: Optional[str] = None, timeout: int = 30) -> Dict[str, Any]:
        """Executes a permitted inspection command or routes code execution to isolated container.
        Strictly forbids user-supplied binary paths, path separators, or arbitrary host execution.
        """
        if not command or not isinstance(command, str):
            return {"success": False, "error": "Command must be a non-empty string identifier."}

        # 1. Reject any path separators, traversal, or special characters in command identifier
        if not re.match(r"^[a-zA-Z0-9_-]+$", command):
            return {
                "success": False,
                "error": f"Invalid command identifier: '{command}'. Path separators, slashes, and traversal characters are strictly prohibited."
            }

        cmd_name = command.lower()

        # 2. Explicitly rejected commands that execute arbitrary code/scripts on host
        BLOCKED_HOST_COMMANDS = {
            "python", "python3", "node", "bash", "sh", "zsh",
            "npm", "pnpm", "yarn", "pytest", "uv"
        }

        if cmd_name in BLOCKED_HOST_COMMANDS:
            # Check if isolated container execution is available
            if IsolatedExecutionProvider.is_isolation_available():
                # Route to isolated disposable container with bare command name (NEVER a host path)
                return IsolatedExecutionProvider.execute_in_container(
                    image="python:3.12-slim" if "py" in cmd_name else "node:20-slim",
                    command=[cmd_name] + args,
                    workspace_mount=cwd,
                    timeout=timeout,
                    task_id=task_id
                )
            return {
                "success": False,
                "error": f"Command '{cmd_name}' is not permitted to execute on the host machine. Host execution of build tools, test runners, and arbitrary interpreters are blocked by security policy."
            }

        if cmd_name not in self.ALLOWED_COMMANDS:
            return {
                "success": False,
                "error": f"Command '{cmd_name}' is not in the local agent command allowlist. Permitted commands: {sorted(list(self.ALLOWED_COMMANDS))}"
            }

        if not self.is_path_safe(cwd):
            return {
                "success": False,
                "error": f"Working directory '{cwd}' is outside permitted directories."
            }

        # 3. Git is handled via safe inspection pipeline
        if cmd_name == "git":
            if not args:
                return {"success": False, "error": "Git command requires a subcommand."}
            subcmd = args[0].lower()
            allowed_subcmds = {"status", "diff", "log", "branch", "show"}
            if subcmd not in allowed_subcmds:
                return {"success": False, "error": f"Git subcommand '{subcmd}' is not permitted. Only {allowed_subcmds} are allowed."}
            return self._execute_safe_git(args, cwd)

        # 4. Echo - Python-native implementation (zero subprocesses spawned)
        if cmd_name == "echo":
            for arg in args:
                if self.METACHO_REGEX.search(arg):
                    return {"success": False, "error": f"Disallowed character in argument: '{arg}'"}
                if ".." in arg:
                    return {"success": False, "error": f"Path traversal in argument: '{arg}'"}
            return {
                "success": True,
                "returncode": 0,
                "stdout": " ".join(args) + "\n",
                "stderr": ""
            }

        # 5. Ls - Python-native implementation (zero subprocesses spawned)
        if cmd_name == "ls":
            allowed_ls_flags = {"-l", "-a", "-la", "-lh", "-lah", "-1"}
            target_dir = cwd
            show_hidden = False
            long_format = False
            for arg in args:
                if self.METACHO_REGEX.search(arg):
                    return {"success": False, "error": f"Disallowed character in argument: '{arg}'"}
                if ".." in arg:
                    return {"success": False, "error": f"Path traversal in argument: '{arg}'"}
                if arg.startswith("-"):
                    if arg not in allowed_ls_flags:
                        return {"success": False, "error": f"Disallowed ls flag: '{arg}'"}
                    if "a" in arg:
                        show_hidden = True
                    if "l" in arg or "1" in arg:
                        long_format = True
                else:
                    target_dir = str(Path(cwd) / arg)

            if not self.is_path_safe(target_dir):
                return {"success": False, "error": f"Target directory outside permitted directories: {target_dir}"}

            try:
                p = Path(target_dir).resolve()
                if not p.is_dir():
                    return {"success": False, "error": f"Not a directory: {target_dir}"}
                entries = []
                for entry in sorted(p.iterdir()):
                    if entry.name.startswith(".") and not show_hidden:
                        continue
                    if self.is_sensitive_file(str(entry)):
                        continue
                    if long_format:
                        st = entry.stat()
                        is_d = "d" if entry.is_dir() else "-"
                        entries.append(f"{is_d}rw-r--r-- {st.st_size:>8} {entry.name}")
                    else:
                        entries.append(entry.name)
                return {
                    "success": True,
                    "returncode": 0,
                    "stdout": "\n".join(entries) + ("\n" if entries else ""),
                    "stderr": ""
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        return {"success": False, "error": f"Unsupported command: '{cmd_name}'"}
