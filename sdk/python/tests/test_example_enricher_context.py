from smithy_python.components.example_enricher_context import (
    main as example_enricher_context_main,
)
import unittest, grpc
from .server import DummyFindingsService
from concurrent import futures
from smithy_python.remote_store.findings_service.v1 import (
    findings_service_pb2_grpc as pb_grpc,
)
from smithy_python.enums.db_type_enum import DBTypeEnum
from .test_data import finding_table
from smithy_python.components.component import Component
import os


class ExampleEnricherContextTest(unittest.TestCase):
    """
    End to end test for the ExampleEnricherContext class in the Smithy Python SDK.
    This test verifies that the ExampleEnricherContext can be used to iterate over findings and update them.
    """

    def setUp(self):
        """
        Set up the test environment by initializing a gRPC server and an ExampleEnricherContext instance.
        """
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        pb_grpc.add_FindingsServiceServicer_to_server(
            DummyFindingsService(), self.server
        )
        self.server.add_insecure_port(f"[::]:50051")
        self.server.start()
        self.instance_id = list(finding_table.keys())[0]
        self.component = Component(
            instance_id=self.instance_id, db_type=DBTypeEnum.REMOTE
        )

    def test_example_enricher_context(self):
        """
        Test the ExampleEnricherContext by iterating over findings and updating them.
        """
        # If everything works correctly this should run without any errors
        # force the page size to 1 to test pagination
        os.environ["SMITHY_REMOTE_CLIENT_PAGE_SIZE"] = "1"
        example_enricher_context_main()

        # Verify that the findings have been updated with the expected annotation comment
        findings = self.component.get_findings()
        self.assertEqual(
            len(findings),
            5,
            "There should be five findings after our update retrieved from the remote database",
        )
        for finding in findings:
            self.assertEqual(
                finding.details.comment,
                "This is a test comment.",
                "Each finding should have the expected annotation comment",
            )

    def tearDown(self):
        """
        Clean up the test environment by stopping the gRPC server.
        """
        self.server.stop(0)
