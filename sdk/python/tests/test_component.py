import unittest, grpc
from smithy_python.components.component import Component
from smithy_python.helpers.logger import log
from .server import DummyFindingsService
from concurrent import futures
from smithy_python.remote_store.findings_service.v1 import (
    findings_service_pb2_grpc as pb_grpc,
)
from smithy_python.enums.db_type_enum import DBTypeEnum
from .test_data import finding_table

class ComponentTest(unittest.TestCase):
    """
    Unit test for the component class in the Smithy Python SDK
    """
    def setUp(self):
        """
        Set up the test environment by initializing a Component instance.
        """

        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        pb_grpc.add_FindingsServiceServicer_to_server(DummyFindingsService(), self.server)
        self.server.add_insecure_port(f"[::]:50051")
        self.server.start()
        self.instance_id = list(finding_table.keys())[0]
        self.component = Component(
            instance_id=self.instance_id,  # Use the first key from the test data
            db_type=DBTypeEnum.REMOTE,
            logger=log
        )


    def test_component_setup(self):
        """
        Test the setup of the Component instance.
        """

        self.assertIsInstance(
            self.component, Component, "Component instance should be of type Component"
        )


    def test_grpc_get_findings(self):
        """
        Test the get_findings method of the Component instance.
        """

        findings = self.component.get_findings()
        
        self.assertListEqual(
            findings, finding_table[self.instance_id], "The findings retrieved should match the expected test data"
        )
    
    def test_grpc_update_findings(self):
        """
        Test the update_findings method of the Component instance.
        """

        temp_component = Component(
            instance_id=list(finding_table.keys())[4],  
            db_type=DBTypeEnum.REMOTE,
            logger=log
        )
        # Update the findings in the remote database
        success = temp_component.update_findings(list(finding_table.values())[2])
        
        self.assertTrue(success, "The findings should be updated successfully")
        
        # Verify that the new finding is now in the database
        updated_findings = temp_component.get_findings()

        self.assertListEqual(list(finding_table.values())[2], updated_findings, "The new finding should be present in the updated findings")
        del temp_component  # Clean up the temporary component instance

    def test_grpc_create_findings(self):
        """
        Test the create_findings method of the Component instance.
        """

        temp_component = Component(
            instance_id=list(finding_table.keys())[5],  
            db_type=DBTypeEnum.REMOTE,
            logger=log
        )

        vuln_findings = []
        for finding in list(finding_table.values())[3]:
            vuln_findings.append(finding.details)
        
        # Create new findings in the remote database
        success = temp_component.create_findings(vuln_findings)
        
        self.assertTrue(success, "The findings should be created successfully")
        
        # Verify that the new finding is now in the database
        created_findings = temp_component.get_findings()

        # We need to compare the actual VulnerabilityFinding objects because the IDs will be different
        self.assertEqual(len(created_findings), len(list(finding_table.values())[3]), "The number of created findings should match the expected count")
        # Check if the created findings match the expected findings
        for finding in created_findings:
            self.assertIn(finding.details, vuln_findings, "Each created finding should match one of the expected findings")
        del temp_component

    def tearDown(self):
        """
        Clean up the test environment
        """
        
        self.server.stop(0)
        del self.component