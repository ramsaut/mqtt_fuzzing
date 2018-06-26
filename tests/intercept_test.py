import unittest
from mqtt_fuzzing.intercept import *
from mqtt_fuzzing.gen_template import *

class TestIntercept(unittest.TestCase):
    def setUp(self):
        reader = TemplateReader()
        self.templates = reader.readTeamplates()

    def test_intercept(self):
        c = ConnectionHandler()
        c.set_templates(self.templates)
        c.start()

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()
