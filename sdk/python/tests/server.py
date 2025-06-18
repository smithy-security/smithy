import time
from concurrent import futures

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from smithy_python.remote_store.findings_service.v1 import (
    findings_service_pb2 as pb,
    findings_service_pb2_grpc as pb_grpc,
)
import smithy_python.ocsf.ocsf_schema.v1.ocsf_schema_pb2 as ocsf

# ──────────────────────────────────────────────────────────────────────────────
# Helper: make a unix-epoch → Timestamp conversion once, reuse it.
def _now_timestamp() -> Timestamp:
    ts = Timestamp()
    ts.GetCurrentTime()           # fills ts with "now"
    return ts

def now() -> tuple[int, Timestamp]:
    """Return (epoch-ms, Timestamp) for 'now'."""
    ms = int(time.time() * 1000)
    ts = Timestamp(); ts.GetCurrentTime()
    return ms, ts
# ──────────────────────────────────────────────────────────────────────────────
class DummyFindingsService(pb_grpc.FindingsServiceServicer):
    """Test implementation that always returns two canned findings."""

    def GetFindings(self, request: pb.GetFindingsRequest, context):
        # Common values
        now_ms = int(time.time() * 1000)
        now_ts = _now_timestamp()

        epoch_ms, ts_now = now()

                # 1️⃣  Build two VulnerabilityFinding payloads
        vuln1 = ocsf.VulnerabilityFinding(
            activity_id = ocsf.VulnerabilityFinding.ACTIVITY_ID_CREATE,
            category_uid= ocsf.VulnerabilityFinding.CATEGORY_UID_FINDINGS,
            class_uid   = ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
            type_uid    = ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
            type_name   = "vulnerability_finding",
            time        = epoch_ms,
            time_dt     = ts_now,
            severity_id = ocsf.VulnerabilityFinding.SEVERITY_ID_HIGH,
            status_id   = ocsf.VulnerabilityFinding.STATUS_ID_NEW,
            finding_info= ocsf.FindingInfo(
                uid          = "FIND-2025-0001",
                title        = "Outdated OpenSSL detected",
                desc         = "Host is running end-of-life OpenSSL 1.0.2-u.",
                created_time = epoch_ms,
                created_time_dt = ts_now,
                types        = ["software_vulnerability"],
            ),
        )

        vuln2 = ocsf.VulnerabilityFinding(
            activity_id = ocsf.VulnerabilityFinding.ACTIVITY_ID_UPDATE,
            category_uid= ocsf.VulnerabilityFinding.CATEGORY_UID_FINDINGS,
            class_uid   = ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
            type_uid    = ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
            type_name   = "vulnerability_finding",
            time        = epoch_ms,
            time_dt     = ts_now,
            severity_id = ocsf.VulnerabilityFinding.SEVERITY_ID_MEDIUM,
            status_id   = ocsf.VulnerabilityFinding.STATUS_ID_IN_PROGRESS,
            finding_info= ocsf.FindingInfo(
                uid          = "FIND-2025-0002",
                title        = "Weak SSH cipher suite",
                desc         = "SSH server allows deprecated arcfour cipher.",
                created_time = epoch_ms,
                created_time_dt = ts_now,
                types        = ["configuration_weakness"],
            ),
        )

        # 2️⃣  Wrap them in the service-level Finding message
        finding1 = pb.Finding(id=1, details=vuln1)
        finding2 = pb.Finding(id=2, details=vuln2)

        # 3️⃣  Return the response
        return pb.GetFindingsResponse(findings=[finding1, finding2])


# ──────────────────────────────────────────────────────────────────────────────
def serve(port: int = 50051) -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pb_grpc.add_FindingsServiceServicer_to_server(DummyFindingsService(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"Dummy FindingsService listening on :{port}")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()