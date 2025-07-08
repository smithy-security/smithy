import unittest
from concurrent import futures
import uuid

import grpc

from smithy.remote_store.findings_service.v1 import (
    findings_service_pb2_grpc as pb_grpc,
)
from smithy.ocsf.ocsf_ext.finding_info.v1 import finding_info_pb2 as ext_pb2
from smithy.ocsf.ocsf_schema.v1 import ocsf_schema_pb2 as ocsf_pb2
from smithy.components.enricher import Enricher
from smithy.components.component import Component
from tests.server import DummyFindingsService
from tests.test_data import finding_table
from smithy.components.runner import Runner
from smithy.enums.db_type_enum import DBTypeEnum


class RunnerTest(unittest.TestCase):
    """
    End to end test for the Runner class in the Smithy Python SDK.
    This test verifies that the Runner takes an Enricher Component Subclass and iterates over findings, calls the enricher and updates them.
    """

    def setUp(self):
        """
        Set up the test environment by initializing a gRPC server and an Runner instance.
        """
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        pb_grpc.add_FindingsServiceServicer_to_server(
            DummyFindingsService(), self.server
        )
        self.server.add_insecure_port(f"[::]:50051")
        self.server.start()
        self.instance_id = list(finding_table.keys())[0]
        self.enricher = self.ExampleEnricher()

    class ExampleEnricher(Enricher):
        """A simple enricher that adds a comment to each finding."""

        def __init__(self):
            super().__init__(None)

        def enrich(self, finding):
            enrichment = ocsf_pb2.Enrichment(
                name="What Kind of Enrichment?",
                provider="ExampleEnricher",  # Optional
                type=str(
                    ext_pb2.Enrichment.EnrichmentType.ENRICHMENT_TYPE_UNSPECIFIED
                ),  # Optional
                value="Enrichment value",
            )

            finding.details.enrichments.append(enrichment)

            return finding

    def test_run(self):
        """Test successful enrichment of findings."""
        runner = Runner(
            component=self.enricher,
            instance_id=self.instance_id,
            db_type=DBTypeEnum.REMOTE,
        )
        runner.run()
        runner = Runner(
            component=self.enricher,
            instance_id=self.instance_id,
            db_type=DBTypeEnum.REMOTE,
        )
        findings = runner._db_manager.get_findings()
        self.assertEqual(
            len(findings),
            5,
            "There should be five findings after our update retrieved from the remote database",
        )
        for finding in findings:
            self.assertEqual(
                finding.details.enrichments[0].name,
                "What Kind of Enrichment?",
                "Each finding should have the expected enrichment name",
            )

    def test_run_with_empty_findings(self):
        """Test runner behavior when there are no findings in the database."""
        # Create a new instance with a non-existent instance_id to simulate empty findings
        fake_instance_id = str(uuid.uuid4())
        runner = Runner(
            component=self.enricher,
            instance_id=fake_instance_id,
            db_type=DBTypeEnum.REMOTE,
        )

        # Should run without errors even with no findings
        runner.run()

        runner = Runner(
            component=self.enricher,
            instance_id=fake_instance_id,
            db_type=DBTypeEnum.REMOTE,
        )
        findings = runner._db_manager.get_findings()
        self.assertEqual(len(findings), 0, "Should handle empty findings gracefully")

    def test_runner_with_invalid_component_type(self):
        """Test that Runner raises appropriate error for unsupported component types."""

        class UnsupportedComponent(Component):
            """A dummy component that's not an Enricher."""

            def __init__(self):
                super().__init__(None)

        unsupported_component = UnsupportedComponent()
        runner = Runner(
            component=unsupported_component,
            instance_id=self.instance_id,
            db_type=DBTypeEnum.REMOTE,
        )

        with self.assertRaises(NotImplementedError) as context:
            runner.run()

        self.assertIn("Only Enricher components are supported", str(context.exception))

    def test_runner_initialization_with_none_component(self):
        """Test that Runner properly validates component parameter."""
        with self.assertRaises(TypeError) as context:
            Runner(
                component=None, instance_id=self.instance_id, db_type=DBTypeEnum.REMOTE
            )

        self.assertIn(
            "component must be an instance of Component", str(context.exception)
        )

    def test_runner_initialization_with_invalid_instance_id(self):
        """Test that Runner properly validates instance_id parameter."""
        with self.assertRaises(TypeError) as context:
            Runner(component=self.enricher, instance_id=None, db_type=DBTypeEnum.REMOTE)

        self.assertIn(
            "instance_id must be a string or UUID object", str(context.exception)
        )

    def test_runner_initialization_with_invalid_uuid(self):
        """Test that Runner properly validates UUID format."""
        with self.assertRaises(ValueError) as context:
            Runner(
                component=self.enricher,
                instance_id="not-a-valid-uuid",
                db_type=DBTypeEnum.REMOTE,
            )

        self.assertIn("instance_id must be a valid UUID", str(context.exception))

    def test_runner_with_enricher_returning_none(self):
        """Test runner behavior when enricher returns None for a finding."""

        class NoneReturningEnricher(self.ExampleEnricher):
            """An enricher that returns None to simulate enrichment failure."""

            def enrich(self, finding):
                return None

        failing_enricher = NoneReturningEnricher()
        runner = Runner(
            component=failing_enricher,
            instance_id=self.instance_id,
            db_type=DBTypeEnum.REMOTE,
        )

        runner.run()
        runner = Runner(
            component=failing_enricher,
            instance_id=self.instance_id,
            db_type=DBTypeEnum.REMOTE,
        )
        findings = runner._db_manager.get_findings()
        self.assertEqual(len(findings), 5, "All findings should still be present")

    def tearDown(self):
        """
        Clean up the test environment by stopping the gRPC server.
        """
        self.server.stop(0)
