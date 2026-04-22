import socket
import os
import stat
from typing import List, Dict, Any


FILE_PERMISSION_BASELINES = {
    "~/.ssh": {"world": 0, "group": 0, "sensitivity": "critical"},
    "~/.bash_history": {"world": 0, "group": stat.S_IRGRP | stat.S_IWGRP, "sensitivity": "sensitive"},
    "/etc/passwd": {"world": stat.S_IROTH, "group": stat.S_IRGRP, "sensitivity": "baseline"},
}


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
            baseline = FILE_PERMISSION_BASELINES.get(path, {"world": 0, "group": 0, "sensitivity": "sensitive"})
            if os.path.exists(expanded_path):
                mode = os.stat(expanded_path).st_mode
                world_bits = mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)
                group_bits = mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP)
                excessive_world_access = bool(world_bits & ~baseline["world"])
                excessive_group_access = bool(group_bits & ~baseline["group"])
                risk = "Info"
                if excessive_world_access:
                    risk = "High"
                elif excessive_group_access:
                    risk = "Medium"
                results.append({
                    "path": path,
                    "exists": True,
                    "mode": oct(mode),
                    "sensitivity": baseline["sensitivity"],
                    "world_accessible": bool(world_bits),
                    "group_accessible": bool(group_bits),
                    "risk": risk,
                })
            else:
                results.append({
                    "path": path,
                    "exists": False,
                    "sensitivity": baseline["sensitivity"],
                    "risk": "Unknown",
                })
        return results

    def run_scan(self) -> Dict[str, Any]:
        open_ports = self.scan_common_ports()
        perm_checks = self.check_file_permissions([
            "~/.ssh",
            "~/.bash_history",
            "/etc/passwd"
        ])
        risky_ports = [port for port in open_ports if port in {21, 23, 25, 3389, 3306, 5432}]
        critical_permission_findings = [p for p in perm_checks if p.get("risk") == "High"]
        
        return {
            "open_ports": open_ports,
            "risky_open_ports": risky_ports,
            "permissions": perm_checks,
            "summary": {
                "critical_issues": len(risky_ports) + len(critical_permission_findings),
                "high_risk_ports": len(risky_ports),
                "high_risk_permission_findings": len(critical_permission_findings),
            }
        }
