"""
This file contains test data for the Smithy Python SDK.
"""

import time
from typing import Dict, List

from google.protobuf.timestamp_pb2 import Timestamp

from smithy.remote_store.findings_service.v1 import findings_service_pb2 as pb
import smithy.ocsf.ocsf_schema.v1.ocsf_schema_pb2 as ocsf


def now() -> tuple[int, Timestamp]:
    ms = int(time.time() * 1000)
    ts = Timestamp()
    ts.GetCurrentTime()
    return ms, ts


epoch_ms, ts_now = now()


_vuln1 = ocsf.VulnerabilityFinding(
    activity_id=ocsf.VulnerabilityFinding.ACTIVITY_ID_CREATE,
    category_uid=ocsf.VulnerabilityFinding.CATEGORY_UID_FINDINGS,
    class_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_name="vulnerability_finding",
    time=epoch_ms,
    time_dt=ts_now,
    severity_id=ocsf.VulnerabilityFinding.SEVERITY_ID_HIGH,
    status_id=ocsf.VulnerabilityFinding.STATUS_ID_NEW,
    finding_info=ocsf.FindingInfo(
        uid="FIND-2025-0001",
        title="Outdated OpenSSL detected",
        desc="Host is running end-of-life OpenSSL 1.0.2-u.",
        created_time=epoch_ms,
        created_time_dt=ts_now,
        types=["software_vulnerability"],
    ),
)

_vuln2 = ocsf.VulnerabilityFinding(
    activity_id=ocsf.VulnerabilityFinding.ACTIVITY_ID_UPDATE,
    category_uid=ocsf.VulnerabilityFinding.CATEGORY_UID_FINDINGS,
    class_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_name="vulnerability_finding",
    time=epoch_ms,
    time_dt=ts_now,
    severity_id=ocsf.VulnerabilityFinding.SEVERITY_ID_MEDIUM,
    status_id=ocsf.VulnerabilityFinding.STATUS_ID_IN_PROGRESS,
    finding_info=ocsf.FindingInfo(
        uid="FIND-2025-0002",
        title="Weak SSH cipher suite",
        desc="SSH server allows deprecated arcfour cipher.",
        created_time=epoch_ms,
        created_time_dt=ts_now,
        types=["configuration_weakness"],
    ),
)

_vuln3 = ocsf.VulnerabilityFinding(
    activity_id=ocsf.VulnerabilityFinding.ACTIVITY_ID_CREATE,
    category_uid=ocsf.VulnerabilityFinding.CATEGORY_UID_FINDINGS,
    class_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_name="vulnerability_finding",
    time=epoch_ms,
    time_dt=ts_now,
    severity_id=ocsf.VulnerabilityFinding.SEVERITY_ID_CRITICAL,
    status_id=ocsf.VulnerabilityFinding.STATUS_ID_NEW,
    finding_info=ocsf.FindingInfo(
        uid="FIND-2025-0003",
        title="Remote Code Execution in Web App",
        desc="Detected RCE vulnerability in /upload endpoint.",
        created_time=epoch_ms,
        created_time_dt=ts_now,
        types=["web_application_vulnerability"],
    ),
)

_vuln4 = ocsf.VulnerabilityFinding(
    activity_id=ocsf.VulnerabilityFinding.ACTIVITY_ID_UPDATE,
    category_uid=ocsf.VulnerabilityFinding.CATEGORY_UID_FINDINGS,
    class_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_name="vulnerability_finding",
    time=epoch_ms,
    time_dt=ts_now,
    severity_id=ocsf.VulnerabilityFinding.SEVERITY_ID_LOW,
    status_id=ocsf.VulnerabilityFinding.STATUS_ID_RESOLVED,
    finding_info=ocsf.FindingInfo(
        uid="FIND-2025-0004",
        title="Information Disclosure via Server Headers",
        desc="Server leaks version info in HTTP headers.",
        created_time=epoch_ms,
        created_time_dt=ts_now,
        types=["information_disclosure"],
    ),
)

_vuln5 = ocsf.VulnerabilityFinding(
    activity_id=ocsf.VulnerabilityFinding.ACTIVITY_ID_CREATE,
    category_uid=ocsf.VulnerabilityFinding.CATEGORY_UID_FINDINGS,
    class_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_uid=ocsf.VulnerabilityFinding.CLASS_UID_VULNERABILITY_FINDING,
    type_name="vulnerability_finding",
    time=epoch_ms,
    time_dt=ts_now,
    severity_id=ocsf.VulnerabilityFinding.SEVERITY_ID_MEDIUM,
    status_id=ocsf.VulnerabilityFinding.STATUS_ID_NEW,
    finding_info=ocsf.FindingInfo(
        uid="FIND-2025-0005",
        title="Unpatched Apache HTTP Server",
        desc="Apache HTTP Server is missing security updates.",
        created_time=epoch_ms,
        created_time_dt=ts_now,
        types=["software_vulnerability"],
    ),
)

_finding1 = pb.Finding(id=1, details=_vuln1)
_finding2 = pb.Finding(id=2, details=_vuln2)
_finding3 = pb.Finding(id=3, details=_vuln3)
_finding4 = pb.Finding(id=4, details=_vuln4)
_finding5 = pb.Finding(id=5, details=_vuln5)
_finding_list1 = [_finding1, _finding2, _finding3, _finding4, _finding5]
_finding_list2 = [_finding1, _finding3, _finding5]
_finding_list3 = [_finding2, _finding4]
_finding_list4 = [_finding3, _finding4, _finding5]
_finding_list5 = [_finding1, _finding2, _finding3]

finding_table: Dict[str, List[pb.Finding]] = {
    "cb5830f7-306a-49cf-ad11-cf31270c6751": _finding_list1,
    "9319a52f-026c-46d0-9d1c-5db89a36fe4a": _finding_list2,
    "b8a8b289-6eff-4643-a23b-deed891c1550": _finding_list3,
    "15d52902-c0fe-4fdb-ac94-a792b8cf6ff6": _finding_list4,
    "baaeae14-d192-43c0-a795-56b3e23882cf": _finding_list5,
    "24eb3430-b176-4442-9a53-58d9e3e0b97a": [],
    "bd324831-7142-47a2-a501-604473c2a662": [],
    "cadd35b6-49cc-4bf3-8ca3-6ca375f5f5b5": [],
    "b76d4a80-ee72-4626-9321-e2f209e5955d": [],
    "9f8ccd6e-3988-4269-aa53-98babf630e6f": [],
}
