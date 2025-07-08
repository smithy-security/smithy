import os
import unittest
from concurrent import futures
from typing import List

import grpc

from smithy.dbmanagers.remote_db_manager import RemoteDBManager
from smithy.remote_store.findings_service.v1 import (
    findings_service_pb2 as pb,
    findings_service_pb2_grpc as pb_grpc,
)
from smithy.remote_store.findings_service.v1.findings_service_pb2 import Finding
from smithy.ocsf.ocsf_schema.v1.ocsf_schema_pb2 import VulnerabilityFinding
from smithy.helpers.logger import log
from tests.server import DummyFindingsService
from tests.test_data import finding_table, _vuln1, _vuln2, _vuln3


class TestRemoteDBManager(unittest.TestCase):
    """
    Comprehensive test suite for the RemoteDBManager class.
    Tests all CRUD operations, pagination, error handling, and configuration options.
    """

    def setUp(self):
        """
        Set up the test environment by starting a gRPC server with test data.
        """
        self.server_port = 50051
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        self.dummy_service = DummyFindingsService()
        pb_grpc.add_FindingsServiceServicer_to_server(self.dummy_service, self.server)
        self.server.add_insecure_port(f"[::]:{self.server_port}")
        self.server.start()

        # Test instance IDs from test_data
        self.instance_id_with_data = (
            "cb5830f7-306a-49cf-ad11-cf31270c6751"  # 5 findings
        )
        self.instance_id_empty = "24eb3430-b176-4442-9a53-58d9e3e0b97a"  # 0 findings
        self.instance_id_partial = "9319a52f-026c-46d0-9d1c-5db89a36fe4a"  # 3 findings

        # Default configuration
        self.default_config = {
            "findings_address": f"localhost:{self.server_port}",
            "max_attempts": "10",
            "initial_backoff_seconds": "5s",
            "max_backoff_seconds": "60s",
            "backoff_multiplier": "1.5",
            "page_size": "100",
        }

    def set_environment_variables(self, optional_config=None):
        """
        Set environment variables for testing based on self.default_config.
        """
        config = self.default_config.copy() if not optional_config else optional_config
        os.environ["SMITHY_REMOTE_STORE_FINDINGS_SERVICE_ADDR"] = config[
            "findings_address"
        ]
        os.environ["SMITHY_REMOTE_CLIENT_MAX_ATTEMPTS"] = config["max_attempts"]
        os.environ["SMITHY_REMOTE_CLIENT_INITIAL_BACKOFF_SECONDS"] = config[
            "initial_backoff_seconds"
        ]
        os.environ["SMITHY_REMOTE_CLIENT_MAX_BACKOFF_SECONDS"] = config[
            "max_backoff_seconds"
        ]
        os.environ["SMITHY_REMOTE_CLIENT_BACKOFF_MULTIPLIER"] = config[
            "backoff_multiplier"
        ]
        os.environ["SMITHY_REMOTE_CLIENT_PAGE_SIZE"] = config["page_size"]

    def tearDown(self):
        """
        Clean up the test environment by stopping the gRPC server.
        """
        self.server.stop(0)

    def reset_server_state(self):
        """
        Reset the server state to original test data.
        """
        import copy
        from tests.test_data import finding_table

        self.dummy_service._groups = copy.deepcopy(finding_table)

    def test_constructor_valid_parameters(self):
        """
        Test that RemoteDBManager initializes correctly with valid parameters.
        """
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        self.assertEqual(db_manager.instance_id, self.instance_id_with_data)
        self.assertEqual(
            db_manager.findings_address, self.default_config["findings_address"]
        )
        self.assertEqual(
            str(db_manager.max_attempts), self.default_config["max_attempts"]
        )
        self.assertEqual(str(db_manager.page_size), self.default_config["page_size"])
        self.assertIsNotNone(db_manager.stub)

    def test_get_findings_all(self):
        """
        Test retrieving all findings without pagination.
        """
        self.reset_server_state()  # Ensure clean state
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        findings = db_manager.get_findings()

        self.assertEqual(len(findings), 5, "Should retrieve all 5 findings")
        self.assertIsInstance(findings[0], Finding)

        # Check that findings have expected structure
        for finding in findings:
            self.assertIsNotNone(finding.id)
            self.assertIsNotNone(finding.details)

    def test_get_findings_empty_dataset(self):
        """
        Test retrieving findings from an instance with no data.
        """
        self.reset_server_state()  # Ensure clean state
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_empty, logger=log)

        findings = db_manager.get_findings()

        self.assertEqual(
            len(findings), 0, "Should return empty list for instance with no data"
        )

    def test_get_findings_with_pagination(self):
        """
        Test retrieving findings with specific page number.
        """
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        # Get first page (page 0)
        page_0_findings = db_manager.get_findings(page_num=0)
        self.assertEqual(
            len(page_0_findings),
            5,
            "Page 0 should return all findings when page_size > total",
        )

        # Test with smaller page size
        small_page_config = self.default_config.copy()
        small_page_config["page_size"] = "2"
        self.set_environment_variables(small_page_config)  # Set small page size

        db_manager_small = RemoteDBManager(
            instance_id=self.instance_id_with_data, logger=log
        )

        page_0_small = db_manager_small.get_findings(page_num=0)
        self.assertEqual(
            len(page_0_small), 2, "Should return 2 findings with page_size=2"
        )

    def test_get_findings_with_custom_page_size(self):
        """
        Test retrieving findings with custom page_size parameter.
        """
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        findings = db_manager.get_findings(page_size=3)
        self.assertGreaterEqual(
            len(findings), 3, "Should return findings with custom page size"
        )

    def test_get_findings_with_environment_page_size_override(self):
        """
        Test pagination behavior when page size is forced to 1 via environment variable.
        Note: This test assumes the RemoteDBManager uses the page_size parameter passed in constructor.
        """
        # Force small page size to test pagination
        small_page_config = self.default_config.copy()
        small_page_config["page_size"] = "1"
        self.set_environment_variables(small_page_config)  # Set small page size

        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        # Get all findings - should still return all despite small page size
        all_findings = db_manager.get_findings()
        self.assertEqual(
            len(all_findings), 5, "Should return all findings despite page_size=1"
        )

        # Get specific page
        page_0_findings = db_manager.get_findings(page_num=0)
        self.assertEqual(
            len(page_0_findings),
            1,
            "Page 0 should return only 1 finding when page_size=1",
        )

    def test_update_findings_success(self):
        """
        Test successful updating of findings.
        """
        self.reset_server_state()  # Ensure clean state
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        # Get existing findings
        findings = db_manager.get_findings()
        self.assertGreater(len(findings), 0, "Should have findings to update")

        # Modify the first finding
        original_comment = (
            findings[0].details.finding_info.desc
            if findings[0].details.finding_info
            else ""
        )
        findings[0].details.comment = "Updated by test"

        # Update the finding
        result = db_manager.update_findings([findings[0]])

        self.assertTrue(result, "Update should succeed")

        # Verify the update
        updated_findings = db_manager.get_findings()
        updated_finding = next(
            (f for f in updated_findings if f.id == findings[0].id), None
        )
        self.assertIsNotNone(updated_finding, "Updated finding should be found")
        self.assertEqual(updated_finding.details.comment, "Updated by test")

    def test_update_findings_empty_list(self):
        """
        Test updating with empty findings list.
        """
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        result = db_manager.update_findings([])

        self.assertFalse(result, "Update with empty list should return False")

    def test_update_findings_invalid_input(self):
        """
        Test updating with invalid input types.
        """
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        # Test with non-list input
        result = db_manager.update_findings("not a list")
        self.assertFalse(result, "Update with invalid input should return False")

        # Test with list of non-Finding objects
        result = db_manager.update_findings(["not", "finding", "objects"])
        self.assertFalse(result, "Update with non-Finding objects should return False")

    def test_create_findings_success(self):
        """
        Test successful creation of new findings.
        """
        self.reset_server_state()  # Ensure clean state
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(
            instance_id=self.instance_id_empty, logger=log  # Use empty instance
        )

        # Verify instance is initially empty
        initial_findings = db_manager.get_findings()
        self.assertEqual(len(initial_findings), 0, "Instance should be empty initially")

        # Create new findings
        new_findings = [_vuln1, _vuln2]
        result = db_manager.create_findings(new_findings)

        self.assertTrue(result, "Create should succeed")

        # Verify findings were created
        created_findings = db_manager.get_findings()
        self.assertEqual(len(created_findings), 2, "Should have 2 new findings")

    def test_create_findings_empty_list(self):
        """
        Test creating with empty findings list.
        """
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_empty, logger=log)

        result = db_manager.create_findings([])

        self.assertFalse(result, "Create with empty list should return False")

    def test_create_findings_invalid_input(self):
        """
        Test creating with invalid input types.
        """
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_empty, logger=log)

        # Test with non-list input
        result = db_manager.create_findings("not a list")
        self.assertFalse(result, "Create with invalid input should return False")

        # Test with list of non-VulnerabilityFinding objects
        result = db_manager.create_findings(["not", "vuln", "objects"])
        self.assertFalse(
            result, "Create with non-VulnerabilityFinding objects should return False"
        )

    def test_batch_operations_with_large_dataset(self):
        """
        Test that operations are properly batched when exceeding page size.
        """
        self.reset_server_state()  # Ensure clean state

        # Use small page size to force batching
        small_page_config = self.default_config.copy()
        small_page_config["page_size"] = "2"
        self.set_environment_variables(small_page_config)  # Set small page size
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        # Get all findings
        findings = db_manager.get_findings()
        self.assertEqual(len(findings), 5, "Should retrieve all findings")

        # Modify all findings
        for i, finding in enumerate(findings):
            finding.details.comment = f"Batch update {i}"

        # Update all findings (should be batched)
        result = db_manager.update_findings(findings)
        self.assertTrue(result, "Batch update should succeed")

        # Verify all updates
        updated_findings = db_manager.get_findings()
        for i, finding in enumerate(updated_findings):
            self.assertEqual(finding.details.comment, f"Batch update {i}")

    def test_connection_cleanup(self):
        """
        Test that gRPC connection is properly cleaned up.
        """
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        # Verify connection exists
        self.assertIsNotNone(db_manager._channel)

        # Trigger cleanup
        del db_manager

        # Note: Testing cleanup is tricky as we can't easily verify
        # the channel was closed, but the test ensures no exceptions are raised

    def test_grpc_error_handling(self):
        """
        Test error handling when gRPC server is not available.
        """
        # Stop the server to simulate connection failure
        self.server.stop(0)

        # Wait a moment for server to fully stop
        import time

        time.sleep(0.1)
        self.set_environment_variables()

        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        # Operations should handle gRPC errors gracefully
        findings = db_manager.get_findings()
        self.assertEqual(
            len(findings), 0, "Should return empty list on connection error"
        )

        # Restart server for cleanup
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        pb_grpc.add_FindingsServiceServicer_to_server(
            DummyFindingsService(), self.server
        )
        self.server.add_insecure_port(f"[::]:{self.server_port}")
        self.server.start()

    def test_validate_findings_list_method(self):
        """
        Test the internal _validate_findings_list method behavior.
        """
        self.set_environment_variables()  # Set environment variables
        db_manager = RemoteDBManager(instance_id=self.instance_id_with_data, logger=log)

        # Valid Finding objects
        findings = db_manager.get_findings()
        if findings:
            self.assertTrue(db_manager._validate_findings_list(findings))

        # Valid VulnerabilityFinding objects
        vuln_findings = [_vuln1, _vuln2]
        self.assertTrue(db_manager._validate_findings_list(vuln_findings))

        # Invalid input types
        self.assertFalse(db_manager._validate_findings_list("not a list"))
        self.assertFalse(db_manager._validate_findings_list(["invalid", "objects"]))
        self.assertFalse(db_manager._validate_findings_list([]))


if __name__ == "__main__":
    unittest.main()
