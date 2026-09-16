"""
OriginTrace Telemetry Receiver
Ingests real-time Falco eBPF alerts via Falcosidekick webhook and dispatches them to the correlation engine.
"""
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, status
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
import json
import os
import time

logger = logging.getLogger("origintrace-receiver")

class FalcoAlertPayload(BaseModel):
    uuid: Optional[str] = None
    output: str
    priority: str
    rule: str
    time: str
    output_fields: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    hostname: Optional[str] = "k8s-node-primary"

class OriginTraceIncidentStore:
    def __init__(self, storage_dir: str = ".origintrace_data"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        self.incidents: List[Dict[str, Any]] = []
        self._load_from_disk()

    def _load_from_disk(self):
        self.incidents = []
        if os.path.exists(self.storage_dir):
            for filename in os.listdir(self.storage_dir):
                if filename.endswith(".json"):
                    try:
                        filepath = os.path.join(self.storage_dir, filename)
                        with open(filepath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            if isinstance(data, dict):
                                self.incidents.append(data)
                    except Exception:
                        continue

    def save_incident(self, incident: Dict[str, Any]) -> str:
        incident_id = f"inc-{int(time.time()*1000)}"
        incident["incident_id"] = incident_id
        incident["received_at"] = time.time()
        self.incidents.append(incident)
        
        filepath = os.path.join(self.storage_dir, f"{incident_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(incident, f, indent=2)
        return incident_id

    def list_incidents(self) -> List[Dict[str, Any]]:
        self._load_from_disk()
        return sorted(self.incidents, key=lambda x: x.get("received_at", 0), reverse=True)

incident_store = OriginTraceIncidentStore()
receiver_app = FastAPI(
    title="OriginTrace Telemetry Ingestion Receiver",
    description="Captures live Falco eBPF security telemetry from Falcosidekick and clusters.",
    version="2.0.0"
)

@receiver_app.post("/webhook/falco", status_code=status.HTTP_202_ACCEPTED)
async def receive_falco_alert(payload: FalcoAlertPayload, background_tasks: BackgroundTasks):
    incident_data = payload.model_dump()
    incident_id = incident_store.save_incident(incident_data)
    logger.info(f"Ingested Falco alert [{payload.priority}] Rule: {payload.rule} -> Assigned ID: {incident_id}")
    
    return {
        "status": "accepted",
        "incident_id": incident_id,
        "rule": payload.rule,
        "priority": payload.priority
    }

@receiver_app.get("/api/v1/incidents")
def get_incidents():
    return {"count": len(incident_store.incidents), "incidents": incident_store.list_incidents()}
