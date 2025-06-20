

from smithy_python.components.example_enricher import ExampleEnricher
import unittest, grpc
from .server import DummyFindingsService
from concurrent import futures
from smithy_python.remote_store.findings_service.v1 import (
    findings_service_pb2_grpc as pb_grpc,
)
from smithy_python.enums.db_type_enum import DBTypeEnum
from .test_data import finding_table

class ExampleEnricherTest(unittest.TestCase):
    """
    Unit test for the ExampleEnricher class in the Smithy Python SDK this serves as a somewhat end to end test.
    """

    def setUp(self):
        """
        Set up the test environment by initializing an ExampleEnricher instance.
        """
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        pb_grpc.add_FindingsServiceServicer_to_server(DummyFindingsService(), self.server)
        self.server.add_insecure_port(f"[::]:50051")
        self.server.start()
        self.instance_id = list(finding_table.keys())[0]
        self.example_enricher = ExampleEnricher(
            instance_id=self.instance_id,
            db_type=DBTypeEnum.REMOTE
        )

    def test_enrich(self):
        """
        Test the enrich method of the ExampleEnricher instance.
        """
        
        self.example_enricher.enrich()
        findings = self.example_enricher.get_findings()
        for finding in findings:
            self.assertEqual(finding.details.comment, "This is an annotated finding.", "Each finding should have the expected annotation comment")
        
    def tearDown(self):
        """
        Clean up the test environment by stopping the gRPC server and deleting everything.
        """
        self.server.stop(0)
        del self.example_enricher