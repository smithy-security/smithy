from logging import Logger
from abc import ABC


class Component(ABC):
    """
    A component in the Smithy Python SDK that represents a component in the smithy framework.
    """

    def __init__(
        self,
        logger: Logger,
    ) -> None:
        """
        Initializes a new instance of the Component class.

        :param logger: An instance of the Logger class for logging.
        :type logger: Logger
        """
        self._log = logger
