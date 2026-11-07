
import json
import hashlib

from app import app
from models import AuditLog

with app.app_context():
    logs = AuditLog.query.order_by(AuditLog.id.asc()).limit(18).all()

    for x in logs:
        data = {
            "actor_id": x.actor_id,
            "document_id": x.document_id,
            "target_user_id": x.target_user_id,
            "action": x.action,
            "status": x.status,
            "details": x.details,
            "ip_address": x.ip_address,
            "created_at": x.created_at.isoformat()
        }

        event_string = json.dumps(data, sort_keys=True)

        calculated_hash = hashlib.sha256(
            ((x.previous_hash or "") + event_string).encode("utf-8")
        ).hexdigest()

        print("\nAudit ID:", x.id)
        print("Action:", x.action)
        print("Details:", repr(x.details))
        print("Stored hash:", x.event_hash)
        print("Calculated hash:", calculated_hash)
        print("Matches:", calculated_hash == x.event_hash)
