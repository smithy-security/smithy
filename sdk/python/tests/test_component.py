import unittest, grpc
from smithy_python.remote_store.findings_service.v1 import findings_service_pb2_grpc, findings_service_pb2
from smithy_python.components.component import Component
from smithy_python.helpers.logger import log
from .server import DummyFindingsService
from concurrent import futures
from smithy_python.remote_store.findings_service.v1 import (
    findings_service_pb2_grpc as pb_grpc,
)


class ComponentTest(unittest.TestCase):

    def setUp(self):
        """
        Set up the test environment by initializing a Component instance.
        """
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        pb_grpc.add_FindingsServiceServicer_to_server(DummyFindingsService(), self.server)
        self.server.add_insecure_port(f"[::]:50051")
        self.server.start()
        self.component = Component(
            instance_id="cb5830f7-306a-49cf-ad11-cf31270c6751",
            db_mode="remote",
            logger=log
        )




    def test_component_setup(self):
        """
        Test the setup of the Component instance.
        """

        self.assertIsInstance(
            self.component, Component, "Component instance should be of type Component"
        )

    def test_component_grpc_connection(self):
        """
        Test the gRPC connection to the remote findings service.
        """
        try:
            response = self.component.get_findings()
            self.assertIsNotNone(response, "Response from GetFindings should not be None")
        except grpc.RpcError as e:
            self.fail(f"gRPC call failed with error: {e}")

    def tearDown(self):
        """
        Clean up the test environment
        """
        
        self.server.stop(0)
        del self.component