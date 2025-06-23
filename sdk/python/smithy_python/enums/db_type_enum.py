from enum import Enum


class DBTypeEnum(Enum):
    """
    Enum for different types of databases implemented for components in the Smithy Python SDK.
    """

    POSTGRES = "postgres"
    SQLITE = "sqlite"
    REMOTE = "remote"
