from contextlib import AbstractContextManager
from smithy_python.components.component import Component
from typing import Iterator, List, Optional, Union
import uuid
from logging import Logger
from smithy_python.enums.db_type_enum import DBTypeEnum
from smithy_python.remote_store.findings_service.v1 import findings_service_pb2 as pb2


class EnricherContext(AbstractContextManager, Component, Iterator):
    """
    This class aims to be used as a context for implementing enrichments in it.
    """

    def __init__(self, instance_id: Union[str, uuid.UUID], db_type: DBTypeEnum, logger: Optional[Logger] = None) -> None:
        """
        Initialize the EnricherContext with an instance ID.

        :param instance_id: The unique identifier for the instance (aka the workflow run) 
        :type instance_id: Union[str, uuid.UUID]
        :param db_type: The type of database being used (REMOTE, SQLITE, POSTGRES).
        :type db_type: DBTypeEnum
        :param logger: An optional logger for logging messages, if no logger is provided, the default logger will be used.
        :type logger: Optional[Logger]
        """

        super().__init__(instance_id=instance_id, db_type=db_type, logger=logger)
        self._iter: Optional[Iterator] = None
        self._pending_updates: List = []               
        self._page = 0
        self._has_more: bool = True              

    def __enter__(self) -> "EnricherContext":
        """
        Enter the context manager, returning the instance itself.

        :return: The instance of EnricherContext.
        :rtype: EnricherContext
        """
        self._page = 0
        self._load_next_page()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """
        Flush any queued updates, then close resources.
        Exceptions propagate (`return False`) unless you decide otherwise.
        """

        if self._pending_updates:
            self._flush_updates()

        if hasattr(self.db_manager, "close"):
            try:
                del self.db_manager
                self.log.debug("DB connection closed.")
            except Exception:
                self.log.exception("Error while closing DB connection")

        return False
    
    def __iter__(self) -> "EnricherContext":      # type: ignore[override]
        return self
    
    def __next__(self) -> pb2.Finding:
        """
        Retrieve the next finding from the iterator.
        :return: The next finding.
        :rtype: pb2.Finding
        :raises StopIteration: If there are no more findings to iterate over.
        """
        
        if self._iter is None:
            raise RuntimeError("EnricherContext must be used inside a 'with' block.")

        try:
            return next(self._iter)    
        except StopIteration:
            if not self._has_more:              
                raise
            self._load_next_page()               
            if not self._has_more:              
                raise StopIteration
            return next(self._iter)        
        

    def _load_next_page(self) -> None:
        """
        Load the next page of findings into the iterator.
        This method is called when the current page has been exhausted.
        """
        results = self.db_manager.get_findings(page_num=self._page)
        self._has_more = bool(results)           
        self._iter = iter(results)
        self._page += 1

    def update(self, finding:pb2.Finding) -> None:
        """
        Queue a mutated finding for persistence. Once the page_size of the db_manager is reached, the updated will be flushed to the DB.

        :param finding: The finding to be updated.
        :type finding: pb2.Finding
        """
        self._pending_updates.append(finding)

        if len(self._pending_updates) >= self.db_manager.page_size:
            self._flush_updates()

    def _flush_updates(self) -> None:
        """
        Write any queued vulnerabilities back to the DB as one bulk call.
        """
        try:
            if not self.db_manager.update_findings(self._pending_updates):
                self.log.error("Failed to update %d findings", len(self._pending_updates))
        finally:
            self._pending_updates.clear()