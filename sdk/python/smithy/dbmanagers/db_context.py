from contextlib import AbstractContextManager
from typing import List, Optional, Iterator
from logging import Logger

from smithy.dbmanagers.db_manager import DBManager
from findings_service.v1 import findings_service_pb2 as pb2


class DBContext(AbstractContextManager, Iterator):
    """
    DBContext is a context manager for database operations.
    It provides methods to get findings from the database with pagination support.
    """

    def __init__(self, db_manager: DBManager, logger: Logger) -> None:
        """
        Initialize the DBContext.

        :param db_manager: The database manager instance to be used for database operations.
        :type db_manager: DBManager

        :param logger: An instance of Logger for logging messages.
        :type logger: Logger

        :raises TypeError: If the db_manager is not an instance of DBManager.
        """

        if not isinstance(db_manager, DBManager):
            raise TypeError("db_manager must be an instance of DBManager.")

        self.db_manager = db_manager
        self._iter: Optional[Iterator] = None
        self._pending_updates: List = []
        self._page = 0
        self._has_more: bool = True
        self._log = logger

    def __enter__(self) -> "DBContext":
        """
        Enter the context manager, returning the instance itself.

        :return: The instance of DBContext.
        :rtype: DBContext
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

        try:
            self.db_manager.close()
            self._log.debug("DB connection closed.")
        except Exception as e:
            self._log.exception(f"Error while closing DB connection: {str(e)}")

        return False

    def __iter__(self) -> "DBContext":
        return self

    def __next__(self) -> pb2.Finding:
        """
        Retrieve the next finding from the iterator.
        :return: The next finding.
        :rtype: pb2.Finding
        :raises StopIteration: If there are no more findings to iterate over.
        """

        if self._iter is None:
            raise RuntimeError("DBContext must be used inside a 'with' block.")

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
        self._has_more = len(results) == self.db_manager.page_size if results else False
        self._iter = iter(results)
        self._page += 1

    def update(self, finding: pb2.Finding) -> None:
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
                self._log.error(
                    "Failed to update %d findings", len(self._pending_updates)
                )
        finally:
            self._pending_updates.clear()
