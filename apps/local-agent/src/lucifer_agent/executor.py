import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Any, List

class ControlledExecutor:
    """Safely executes permitted commands and file operations inside allowlisted directories.
    Strictly forbids arbitrary interpreters (python, bash, sh, node) and enforces
    per-command argument allowlists.
    """

    # Strictly restricted set of tools (NO generic interpreters like python, bash, sh)
    ALLOWED_COMMANDS = {
        "git",
        "pytest",
        "npm",
        "pnpm",
        "uv",
        "echo",
        "ls"
    }

    # Block any shell metacharacters or dangerous control codes
    METACHO_REGEX = re.compile(r"[;&|`$\n\r><\(\)\{\}\[\]!]")

    # Sensitive files that must NEVER be read even if located inside allowed directories
    SENSITIVE_FILE_PATTERNS = [
        re.compile(r"(^|/)\.env(\..+)?$"),
        re.compile(r"(^|/)\.git/config$"),
        re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)"),
        re.compile(r"\.(pem|key|p12|pfx|pkcs12)$"),
        re.compile(r"(^|/)(credentials|\.netrc|\.npmrc|\.aws/credentials)$")
    ]

    def __init__(self, allowed_directories: List[str]):
        self.allowed_directories = [Path(d).resolve() for d in allowed_directories]

    def is_path_safe(self, target_path: str) -> bool:
        """Ensures path stays within allowlisted directories and prevents traversal."""
        try:
            resolved = Path(target_path).resolve()
            return any(resolved == allowed or allowed in resolved.parents for allowed in self.allowed_directories)
        except Exception:
            return False

    def validate_command_arguments(self, cmd_name: str, args: List[str]) -> Dict[str, Any]:
        """Validates command-specific arguments against strict capability allowlists."""
        # 1. Check for shell metacharacters in all arguments
        for arg in args:
            if self.METACHO_REGEX.search(arg):
                return {"valid": False, "error": f"Disallowed character in argument: '{arg}'"}
            if ".." in arg:
                return {"valid": False, "error": f"Path traversal ('..') disallowed in argument: '{arg}'"}

        # 2. Command-specific validation
        if cmd_name == "git":
            if not args:
                return {"valid": False, "error": "Git command requires a subcommand."}
            subcmd = args[0].lower()
            allowed_subcmds = {"status", "diff", "log", "branch", "show"}
            if subcmd not in allowed_subcmds:
                return {"valid": False, "error": f"Git subcommand '{subcmd}' is not permitted. Only {allowed_subcmds} are allowed."}
            # Disallow dangerous flags
            for arg in args[1:]:
                if arg.startswith("-C") or arg.startswith("--config") or arg == "-c" or arg.startswith("--upload-pack"):
                    return {"valid": False, "error": f"Dangerous git flag disallowed: '{arg}'"}

        elif cmd_name == "pytest":
            # Allow flags like -v, -q, -k <filter>, or test paths
            disallowed_pytest_flags = {"-o", "--override-ini", "-c", "--import-mode", "--assert", "-p", "--pyargs"}
            for arg in args:
                if any(arg == f or arg.startswith(f + "=") for f in disallowed_pytest_flags):
                    return {"valid": False, "error": f"Dangerous pytest flag disallowed: '{arg}'"}

        elif cmd_name in ("npm", "pnpm"):
            if not args:
                return {"valid": False, "error": f"{cmd_name} requires a subcommand."}
            subcmd = " ".join(args[:2]).lower() if len(args) >= 2 and args[0] == "run" else args[0].lower()
            allowed_npm = {"test", "run test", "run build", "run lint", "run typecheck"}
            if subcmd not in allowed_npm:
                return {"valid": False, "error": f"{cmd_name} subcommand '{subcmd}' is not permitted. Only {allowed_npm} are allowed."}

        elif cmd_name == "uv":
            if len(args) < 2 or args[0] != "run" or args[1] not in ("pytest", "test"):
                return {"valid": False, "error": "uv command only permitted for 'uv run pytest' or 'uv run test'."}

        elif cmd_name == "ls":
            allowed_ls_flags = {"-l", "-a", "-la", "-lh", "-lah", "-1"}
            for arg in args:
                if arg.startswith("-") and arg not in allowed_ls_flags:
                    return {"valid": False, "error": f"Disallowed ls flag: '{arg}'"}

        elif cmd_name == "echo":
            pass

        return {"valid": True}

    def execute_command(self, command: str, args: List[str], cwd: str) -> Dict[str, Any]:
        """Executes a structured command without shell interpolation with capability checks."""
        cmd_name = Path(command).name
        if cmd_name not in self.ALLOWED_COMMANDS:
            return {
                "success": False,
                "error": f"Command '{cmd_name}' is not in the local agent command allowlist (arbitrary interpreters are blocked)."
            }

        if not self.is_path_safe(cwd):
            return {
                "success": False,
                "error": f"Working directory '{cwd}' is outside permitted directories."
            }

        # Validate arguments against capability policy
        val = self.validate_command_arguments(cmd_name, args)
        if not val["valid"]:
            return {
                "success": False,
                "error": f"Security policy rejected arguments: {val['error']}"
            }

        cmd_list = [command] + args
        try:
            proc = subprocess.run(
                cmd_list,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False # Strictly avoid shell injection
            )
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": proc.stdout[:10000], # Limit output size
                "stderr": proc.stderr[:5000]
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Execution timed out (30s limit)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def read_file(self, file_path: str) -> Dict[str, Any]:
        """Reads a file safely if within allowed projects and not sensitive."""
        if not self.is_path_safe(file_path):
            return {"success": False, "error": f"Access denied to file: {file_path}"}

        p = Path(file_path).resolve()
        if not p.is_file():
            return {"success": False, "error": f"File does not exist: {file_path}"}

        # Check for sensitive credentials/keys
        path_str = str(p)
        for pattern in self.SENSITIVE_FILE_PATTERNS:
            if pattern.search(path_str):
                return {"success": False, "error": f"Access to sensitive file '{p.name}' is strictly blocked."}

        if p.stat().st_size > 1024 * 512: # 512 KB limit
            return {"success": False, "error": "File size exceeds 512KB limit"}

        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            return {"success": True, "content": content}
        except Exception as e:
            return {"success": False, "error": str(e)}
