import unittest

from smithy_python.components.component import Component


class ComponentTest(unittest.TestCase):

    def setUp(self):
        """
        Set up the test environment by initializing a Component instance.
        """

        self.component = Component()

    def test_component_setup(self):
        """
        Test the setup of the Component instance.
        """

        self.assertIsInstance(
            self.component, Component, "Component instance should be of type Component"
        )

    def tearDown(self):
        """
        Clean up the test environment by closing the temporary directories.
        """
        # No specific cleanup needed for DiffExaminer
        pass
