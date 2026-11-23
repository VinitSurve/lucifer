import requests
from typing import Dict, Any, List

class OllamaClient:
    def __init__(self, base_url: str = "http://127.0.0.1:11434"):
        self.base_url = base_url.rstrip("/")

    def check_health(self) -> Dict[str, Any]:
        """Checks if local Ollama daemon is active and lists available models."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                return {
                    "running": True,
                    "models": models,
                    "model_count": len(models)
                }
            return {"running": False, "models": [], "error": f"Status {resp.status_code}"}
        except Exception as e:
            return {"running": False, "models": [], "error": str(e)}

    def generate(self, model: str, prompt: str) -> str:
        """Runs local model inference."""
        resp = requests.post(
            f"{self.base_url}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=60
        )
        resp.raise_for_status()
        return resp.json().get("response", "")
