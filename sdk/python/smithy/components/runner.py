from typing import Optional, Union
import uuid
from logging import Logger

from smithy.components.component import Component
from smithy.components.enricher import Enricher
from smithy.dbmanagers.db_context import DBContext
from smithy.enums.db_type_enum import DBTypeEnum
from smithy.helpers.logger import log
from smithy.dbmanagers.resolver import Resolver


class Runner:
    """
    The Runner class is responsible for executing the main logic of a given component. Depending on the Component's type.
    """

    def __init__(
        self,
        component: Component,
        instance_id: Union[uuid.UUID, str],
        db_type: DBTypeEnum,
        logger: Optional[Logger] = None,
    ) -> None:
        """
        Initializes the Runner with a given component.

        :param component: An instance of the Component class to be executed.
        :type component: Component

        :param instance_id: The UUID (v4) of the instance (aka the Workflow run to be analyzed)
        :type instance_id: Union[uuid.UUID, str]

        :param db_type: The type of database being used (REMOTE, SQLITE, POSTGRES).
        :type db_type: DBTypeEnum

        :raises TypeError: If the component is not an instance of Component.
        :raises ValueError: If the instance_id is not a valid UUID.
        :raises TypeError: If the instance_id is not a string or UUID object, or the logger is not an instance of Logger or None.
        """

        if not isinstance(component, Component):
            raise TypeError("component must be an instance of Component.")

        self.component = component

        if not logger:
            self._log = log
        elif isinstance(logger, Logger):
            self._log = logger
        else:
            raise TypeError("logger must be an instance of Logger or None.")

        if instance_id is None or (
            not isinstance(instance_id, str) and not isinstance(instance_id, uuid.UUID)
        ):
            raise TypeError("instance_id must be a string or UUID object.")

        if isinstance(instance_id, uuid.UUID):
            if instance_id.version == 4:
                instance_id = str(instance_id)
            else:
                raise ValueError("instance_id must be a UUID version 4.")

        try:
            instance_id = uuid.UUID(instance_id, version=4)
        except ValueError as e:
            raise ValueError("instance_id must be a valid UUID.") from e

        resolver = Resolver(logger=self._log)
        self._db_manager = resolver.resolve(instance_id=instance_id, db_type=db_type)

        self.db_context = DBContext(db_manager=self._db_manager, logger=self._log)

    def run(self) -> None:
        """
        Executes the main logic of the component.

        This method is responsible for running the component's logic.
        """

        if isinstance(self.component, Enricher):
            self._run_enricher()
        else:
            self._log.error(
                f"Unsupported component type: {type(self.component)}. Only Enricher components are supported."
            )
            raise NotImplementedError(
                "Only Enricher components are supported in the current implementation."
            )

    def _run_enricher(self) -> None:
        """
        Runs the logic for the Enricher component.

        This method is responsible for executing the enrichment logic of the component.
        """

        with self.db_context as db:
            for finding in db:
                try:
                    enriched_finding = self.component.enrich(finding)
                    if enriched_finding:
                        db.update(enriched_finding)
                    else:
                        self._log.warning(
                            f"Enrichment failed for finding ID: {finding.id}"
                        )
                except Exception as e:
                    self._log.error(
                        f"Error during enrichment for finding ID: {finding.id}. Error: {e}"
                    )
                    continue
