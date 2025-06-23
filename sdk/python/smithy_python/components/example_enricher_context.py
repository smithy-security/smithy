from .enricher_context import EnricherContext
from smithy_python.enums.db_type_enum import DBTypeEnum


def main():
    """
    Main function to demonstrate the usage of EnricherContext.
    """

    with EnricherContext(
        instance_id="cb5830f7-306a-49cf-ad11-cf31270c6751", db_type=DBTypeEnum.REMOTE
    ) as context:
        for finding in context:
            # print(f"Finding ID: {finding.id}, Details: {finding.details}")
            finding.details.comment = "This is a test comment."
            context.update(finding)


if __name__ == "__main__":
    main()
