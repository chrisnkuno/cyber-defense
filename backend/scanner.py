import socket
import os
import stat
from typing import List, Dict, Any

class SecurityScanner:
    @staticmethod
    def scan_common_ports(host: str = "127.0.0.1", ports: List[int] = None) -> List[int]:
        if ports is None:
            ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080]
        
        open_ports = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(port)
        return open_ports

    @staticmethod
    def check_file_permissions(paths: List[str]) -> List[Dict[str, Any]]:
        results = []
        for path in paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                mode = os.stat(expanded_path).st_mode
                # Check if world readable/writable/executable
                is_world_accessible = bool(mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH))
                results.append({
                    "path": path,
                    "exists": True,
                    "mode": oct(mode),
                    "world_accessible": is_world_accessible,
                    "risk": "High" if is_world_accessible else "Low"
                })
            else:
                results.append({"path": path, "exists": False})
        return results

    def run_scan(self) -> Dict[str, Any]:
        open_ports = self.scan_common_ports()
        perm_checks = self.check_file_permissions([
            "~/.ssh",
            "~/.bash_history",
            "/etc/passwd"
        ])
        
        return {
            "open_ports": open_ports,
            "permissions": perm_checks,
            "summary": {
                "critical_issues": len(open_ports) + sum(1 for p in perm_checks if p.get("risk") == "High")
            }
        }
