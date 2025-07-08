from concurrent import futures

import grpc

from smithy.remote_store.findings_service.v1 import (
    findings_service_pb2 as pb,
    findings_service_pb2_grpc as pb_grpc,
)
from smithy.remote_store.findings_service.v1.findings_service_pb2 import Finding
from tests.test_data import finding_table


class DummyFindingsService(pb_grpc.FindingsServiceServicer):
    """Test implementation that always returns two canned findings."""

    def __init__(self) -> None:
        # maps request.id → list[pb.Finding] (for Update) OR
        #                    list[ocsf.VulnerabilityFinding] (for Create)
        self._groups = finding_table.copy()  # pre-populate with test data

    def GetFindings(self, request: pb.GetFindingsRequest, context):

        if not request.id:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "id is required")

        findings = self._groups.get(request.id, [])
        page_size = request.page_size
        page = int(request.page) if request.page else 0

        start = page * page_size
        end = start + page_size

        return pb.GetFindingsResponse(findings=findings[start:end])

    def CreateFindings(
        self, request: pb.CreateFindingsRequest, context
    ) -> pb.CreateFindingsResponse:
        """
        Simply stores the supplied VulnerabilityFinding messages under
        request.id.  If that ID already exists, we append.
        """
        if not request.id:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "id is required")

        group = self._groups.setdefault(request.id, [])
        id = max((f.id for f in group), default=0) + 1  # find next ID
        for finding in request.findings:
            group.append(Finding(id=id, details=finding))
            id += 1
        return pb.CreateFindingsResponse()

    # --------------------------------------------------------------------- #
    # New RPC: *UpdateFindings*
    # --------------------------------------------------------------------- #
    def UpdateFindings(
        self, request: pb.UpdateFindingsRequest, context
    ) -> pb.UpdateFindingsResponse:
        """
        Replaces any existing findings for request.id with the supplied list.
        If the id did not exist yet, we create it (simpler for tests).
        """
        if not request.id:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "id is required")

        for finding in request.findings:
            if not finding.id:
                context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT, "finding.id is required"
                )
            group = self._groups.setdefault(request.id, [])
            # Find the existing finding by ID and replace it, or append if not found
            for i, existing_finding in enumerate(group):
                if existing_finding.id == finding.id:
                    group[i] = Finding(id=finding.id, details=finding.details)
                    break
            else:
                # If not found, append the new finding
                group.append(Finding(id=finding.id, details=finding.details))

        self._groups[request.id] = group
        return pb.UpdateFindingsResponse()


def serve(port: int = 50051) -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pb_grpc.add_FindingsServiceServicer_to_server(DummyFindingsService(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
