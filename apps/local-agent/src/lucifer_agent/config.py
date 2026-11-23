import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List

@dataclass
class AgentConfig:
    cloud_url: str = os.getenv("LUCIFER_CLOUD_URL", "http://127.0.0.1:8787")
    device_id: str = os.getenv("LUCIFER_DEVICE_ID", "mac-local-default")
    device_name: str = os.getenv("LUCIFER_DEVICE_NAME", "Lucifer macOS Workstation")
    auth_secret: str = os.getenv("LUCIFER_AGENT_SECRET", "local_development_secret")
    ollama_url: str = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
    poll_interval_seconds: int = int(os.getenv("LUCIFER_POLL_INTERVAL", "5"))
    heartbeat_interval_seconds: int = int(os.getenv("LUCIFER_HEARTBEAT_INTERVAL", "30"))
    allowed_directories: List[str] = field(default_factory=lambda: [
        str(Path.home() / "Vinit"),
        str(Path.home() / "Projects"),
        str(Path.home() / "Documents")
    ])
