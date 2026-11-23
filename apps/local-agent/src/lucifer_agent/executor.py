import os
import subprocess
from pathlib import Path
from typing import Dict, Any, List

class ControlledExecutor:
    """Safely executes permitted commands and file operations inside allowlisted directories."""

    # Explicit allowlist of permissible CLI tools
    ALLOWED_COMMANDS = {
        "git",
        "pytest",
        "npm",
        "pnpm",
        "uv",
        "python3",
        "echo",
        "ls"
    }

    def __init__(self, allowed_directories: List[str]):
        self.allowed_directories = [Path(d).resolve() for d in allowed_directories]

    def is_path_safe(self, target_path: str) -> bool:
        """Ensures path stays within allowlisted directories and prevents traversal."""
        try:
            resolved = Path(target_path).resolve()
            return any(resolved == allowed or allowed in resolved.parents for allowed in self.allowed_directories)
        except Exception:
            return False

    def execute_command(self, command: str, args: List[str], cwd: str) -> Dict[str, Any]:
        """Executes a structured command without shell interpolation."""
        cmd_name = Path(command).name
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
        """Reads a file safely if within allowed projects."""
        if not self.is_path_safe(file_path):
            return {"success": False, "error": f"Access denied to file: {file_path}"}

        p = Path(file_path)
        if not p.is_file():
            return {"success": False, "error": f"File does not exist: {file_path}"}

        if p.stat().st_size > 1024 * 512: # 512 KB limit
            return {"success": False, "error": "File size exceeds 512KB limit"}

        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            return {"success": True, "content": content}
        except Exception as e:
            return {"success": False, "error": str(e)}
