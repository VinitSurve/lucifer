import time
import requests
from typing import Optional, Dict, Any
from .config import AgentConfig
from .sysinfo import get_system_metrics
from .ollama_client import OllamaClient
from .executor import ControlledExecutor

class AgentDaemon:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.ollama = OllamaClient(config.ollama_url)
        self.executor = ControlledExecutor(config.allowed_directories)
        self.running = False

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.auth_secret}",
            "Content-Type": "application/json"
        }

    def send_heartbeat(self) -> bool:
        """Sends outbound device heartbeat to Lucifer Cloud with Bearer authentication."""
        metrics = get_system_metrics()
        ollama_status = self.ollama.check_health()
        payload = {
            "deviceId": self.config.device_id,
            "deviceName": self.config.device_name,
            "info": {
                **metrics,
                "ollamaRunning": ollama_status.get("running", False),
                "ollamaModels": ollama_status.get("models", [])
            }
        }

        try:
            url = f"{self.config.cloud_url.rstrip('/')}/api/agent/heartbeat"
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def poll_task(self) -> Optional[Dict[str, Any]]:
        """Polls cloud queue for leased task with Bearer authentication."""
        url = f"{self.config.cloud_url.rstrip('/')}/api/agent/poll"
        try:
            resp = requests.post(url, json={"deviceId": self.config.device_id}, headers=self._get_headers(), timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("task")
            return None
        except Exception:
            return None

    def submit_result(self, task_id: str, success: bool, result: Any = None, error: str = None) -> bool:
        """Reports task result back to cloud with Bearer authentication and device ownership."""
        url = f"{self.config.cloud_url.rstrip('/')}/api/agent/result"
        payload = {
            "deviceId": self.config.device_id,
            "taskId": task_id,
            "success": success,
            "result": result,
            "error": error
        }
        try:
            resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def execute_task(self, task: Dict[str, Any]) -> None:
        """Executes a dispatched local task."""
        task_id = task.get("id")
        task_type = task.get("type")
        payload = task.get("payload") or {}

        try:
            if task_type == "mac_sysinfo":
                metrics = get_system_metrics()
                self.submit_result(task_id, True, result=metrics)
            elif task_type == "mac_read_file":
                fp = payload.get("filePath")
                res = self.executor.read_file(fp)
                self.submit_result(task_id, res.get("success", False), result=res.get("content"), error=res.get("error"))
            elif task_type == "mac_run_command":
                cmd = payload.get("command")
                args = payload.get("args") or []
                cwd = payload.get("cwd") or str(self.config.allowed_directories[0])
                res = self.executor.execute_command(cmd, args, cwd)
                self.submit_result(task_id, res.get("success", False), result=res, error=res.get("error"))
            else:
                self.submit_result(task_id, False, error=f"Unknown task type: {task_type}")
        except Exception as e:
            self.submit_result(task_id, False, error=str(e))

    def run_loop(self) -> None:
        """Main agent polling loop."""
        self.running = True
        last_heartbeat = 0

        while self.running:
            now = time.time()
            if now - last_heartbeat >= self.config.heartbeat_interval_seconds:
                self.send_heartbeat()
                last_heartbeat = now

            task = self.poll_task()
            if task:
                self.execute_task(task)

            time.sleep(self.config.poll_interval_seconds)
