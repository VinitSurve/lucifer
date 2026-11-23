import platform
import psutil
from typing import Dict, Any

def get_system_metrics() -> Dict[str, Any]:
    """Collects hardware and OS metrics without collecting private files."""
    cpu_pct = psutil.cpu_percent(interval=0.1)
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "platform_version": platform.mac_ver()[0] if hasattr(platform, 'mac_ver') else platform.version(),
        "arch": platform.machine(),
        "python_version": platform.python_version(),
        "cpu_percent": cpu_pct,
        "ram_total_gb": round(vm.total / (1024 ** 3), 2),
        "ram_used_percent": vm.percent,
        "disk_free_gb": round(disk.free / (1024 ** 3), 2),
        "disk_total_gb": round(disk.total / (1024 ** 3), 2)
    }
