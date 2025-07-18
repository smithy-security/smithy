import os
from logging import Logger
from typing import List, Optional, Union, override

import grpc

from smithy.dbmanagers.db_manager import DBManager
from smithy.remote_store.findings_service.v1.findings_service_pb2_grpc import (
    FindingsServiceStub,
)
from smithy.remote_store.findings_service.v1.findings_service_pb2 import (
    GetFindingsRequest,
    Finding,
    UpdateFindingsRequest,
    CreateFindingsRequest,
)
from smithy.ocsf.ocsf_schema.v1.ocsf_schema_pb2 import VulnerabilityFinding


class RemoteDBManager(DBManager):
    """
    This class is used to manage remote database connections.
    It extends the DBManager class and implements the required methods for managing remote database connections.
    """

    def __init__(
        self,
        instance_id: str,
        logger: Optional[Logger] = None,
    ) -> None:
        """
        Initializes the RemoteDBManager
        :param instance_id: The UUID of the instance (aka the Workflow run to be analyzed)
        :type instance_id: str
        :param logger: An instance of the Logger class for logging. If not provided, a default logger will be used.
        :type logger: Optional[Logger]
        :raises TypeError: If the logger is not an instance of Logger or None.
        """

        super().__init__(instance_id, logger)
        self._log.debug(f"RemoteDBManager initialized with instance_id: {instance_id}")
        self._load_remote_db_env_vars()
        self._channel = grpc.insecure_channel(self.findings_address)
        self._log.debug(f"gRPC channel created for address: {self.findings_address}")

        self.stub = FindingsServiceStub(self._channel)

    @override
    def get_findings(
        self, page_num: Optional[int] = None, page_size: Optional[int] = None
    ) -> List[Finding]:
        """
        Retrieves findings from the remote database which are associated with the class variable `instance_id`.

        If `page_num` is provided, it retrieves a single page of findings.
        If `page_num` is not provided, it retrieves all findings by paginating through all available pages.

        :param page_num: Optional parameter to specify the page number for pagination. If provided, only this page will be retrieved.
        :type page_num: Optional[int]

        :param page_size: Optional parameter to specify the number of findings per page. If not provided, the page size specified by the ENV variable `SMITHY_REMOTE_CLIENT_PAGE_SIZE` will be used (default is 100).
        :type page_size: Optional[int]

        :return: A list of findings retrieved from the remote database.
        """
        self._log.debug(
            f"get_findings called with page_num: {page_num}, page_size: {page_size}"
        )

        page = 0
        get_findings_page_size = self.page_size

        if isinstance(page_num, int) and page_num >= 0:
            page = page_num
           
        if isinstance(page_size, int) and page_size > 0:
            get_findings_page_size = page_size

        if page_size and page_num is None:
            self._log.warning(
                "page_size is provided but page_num is not. Defaulting to page_num 0."
            )

        all_findings = []
        try:
            while True:
                self._log.debug(f"Requesting page {page} with page_size {get_findings_page_size}")
                request = GetFindingsRequest(
                    id=self.instance_id, page=page, page_size=get_findings_page_size
                )

                resp = self.stub.GetFindings(request)
                self._log.debug(f"Received {len(resp.findings)} findings in response for page {page}.")

                all_findings.extend(resp.findings)

                # Break conditions
                if page_num is not None:
                    self._log.debug(f"page_num ({page_num}) was specified, breaking loop after one page.")
                    break
                if not resp.findings or len(resp.findings) < get_findings_page_size:
                    self._log.debug("No more findings or last page reached. Breaking loop.")
                    break

                page += 1
        except grpc.RpcError as e:
            self._log.error(f"Failed to retrieve findings from remote database: {e}")

        self._log.debug(f"get_findings returning {len(all_findings)} total findings.")
        return all_findings

    @override
    def update_findings(self, findings: List[Finding]) -> bool:
        """
        Update the given findings in the remote database.

        :param findings: A list of findings to update in the remote database.
        :type findings: List[Finding]
        :return: True if the update was successful, False otherwise.
        :rtype: bool
        """

        if not self._validate_findings_list(findings):
            return False

        try:
            for i in range(0, len(findings), self.page_size):
                batch = findings[i : i + self.page_size]
                self.stub.UpdateFindings(
                    UpdateFindingsRequest(id=self.instance_id, findings=batch)
                )
        except grpc.RpcError as e:
            self._log.error(f"Failed to update findings in remote database: {e}")
            return False

        return True

    @override
    def create_findings(self, findings: List[VulnerabilityFinding]) -> bool:
        """
        Create the new findings in the remote database.

        :param findings: A list of VulnerabilityFindings to create in the remote database. (Note: This needs to be a list of VulnerabilityFinding objects, not Finding objects, because we creat the associated unique IDs for each finding in the remote database.)
        :type findings: List[VulnerabilityFinding]
        :return: True if the creation was successful, False otherwise.
        """

        if not self._validate_findings_list(findings):
            return False

        try:
            for i in range(0, len(findings), self.page_size):
                batch = findings[i : i + self.page_size]
                self.stub.CreateFindings(
                    CreateFindingsRequest(id=self.instance_id, findings=batch)
                )

        except grpc.RpcError as e:
            self._log.error(f"Failed to create findings in remote database: {e}")
            return False

        return True

    @override
    def close(self) -> None:
        """
        Closes the gRPC channel to the remote database.

        This method should be called when the RemoteDBManager is no longer needed to release resources.
        """

        if hasattr(self, "_channel") and self._channel:
            self._channel.close()
            self._log.info("Closed gRPC channel to remote database.")

    def __del__(self):
        """
        Cleans up the RemoteDBManager instance.
        Closes the gRPC channel when the instance is deleted.
        """

        if hasattr(self, "_channel") and self._channel:
            self._channel.close()

    def _validate_findings_list(
        self, findings: Union[List[Finding], List[VulnerabilityFinding]]
    ) -> bool:
        """
        Validates the findings list to ensure it contains only Finding objects.

        :param findings: The list of findings to validate.
        :type findings: List[Finding]
        :return: True if the list is valid, False otherwise.
        """

        if not isinstance(findings, list) or not all(
            isinstance(finding, (Finding, VulnerabilityFinding)) for finding in findings
        ):
            self._log.error(
                "Invalid or findings provided for update. Must be a list of Finding objects."
            )
            return False

        if not findings:
            self._log.warning("No findings provided for update. Skipping update.")
            return False

        self._log.info(f"Valid findings list provided!")
        return True

    def _load_remote_db_env_vars(self):
        """
        Loads all the environment variables required for the remote database connection.
        """

        self.findings_address = os.getenv(
            "SMITHY_REMOTE_STORE_FINDINGS_SERVICE_ADDR", "localhost:50051"
        )
        self.max_attempts = int(os.getenv("SMITHY_REMOTE_CLIENT_MAX_ATTEMPTS", 10))
        self.initial_backoff_seconds = os.getenv(
            "SMITHY_REMOTE_CLIENT_INITIAL_BACKOFF_SECONDS", "5s"
        )
        self.max_backoff_seconds = os.getenv(
            "SMITHY_REMOTE_CLIENT_MAX_BACKOFF_SECONDS", "60s"
        )
        self.backoff_multiplier = float(
            os.getenv("SMITHY_REMOTE_CLIENT_BACKOFF_MULTIPLIER", 1.5)
        )
        self.page_size = int(os.getenv("SMITHY_REMOTE_CLIENT_PAGE_SIZE", 100))
