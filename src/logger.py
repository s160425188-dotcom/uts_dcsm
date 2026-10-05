import json
from datetime import datetime

class AuditLogger:
    def __init__(self, log_file="audit_logs.json"):
        self.log_file = log_file

    def log(self, user: str, role: str, action: str, resource: str, decision: str, reason: str = ""):
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user": user,
            "role": role,
            "action": action,
            "resource": resource,
            "decision": decision,  # ALLOW / DENY
            "reason": reason
        }
        print(f"[AUDIT LOG] {json.dumps(entry)}")
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

audit_logger = AuditLogger()
