from abc import abstractmethod, ABC
from logging import Logger
from typing import Optional

from smithy.components.component import Component
from smithy.remote_store.findings_service.v1 import findings_service_pb2 as pb2
from smithy.ocsf.ocsf_schema.v1 import ocsf_schema_pb2 as ocsf_pb2
from smithy.ocsf.ocsf_ext.finding_info.v1 import finding_info_pb2 as ext_pb2


class Enricher(Component, ABC):
    """
    An enricher is a component in the Smithy Python SDK that represents an enricher in the smithy framework.
    Enrichers are used to add context or additional information to findings.
    """

    def __init__(
        self,
        logger: Optional[Logger] = None,
    ) -> None:
        """
        Initializes a new instance of the Enricher class.
        :param logger: An instance of the Logger class for logging. If not provided, a default logger will be used.
        :type logger: Optional[Logger]
        """

        super().__init__(logger)

    @abstractmethod
    def enrich(self, finding: pb2.Finding) -> pb2.Finding:
        """
        Enriches the given finding and returns the enriched finding.
        """

        raise NotImplementedError(
            "The enrich method must be implemented by subclasses of Enricher."
        )

        # EXAMPLE
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
        # END EXAMPLE
