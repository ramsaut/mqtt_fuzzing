import unittest
from mqtt_fuzzing.gen_template import *
from scapy.contrib.mqtt import *

logger = logging.getLogger(__name__)
logger.setLevel('INFO')


class TestGenerator(unittest.TestCase):
    generator = TemplateGenerator()

    @unittest.skip
    def test_read_capture(self):
        self.generator.read_capture()

    def test_create_templates(self):
        list = self.generator.read_capture()
        templates = self.generator.create_templates(list)
        self.generator.save_to_disk(templates)


class TestReader(unittest.TestCase):
    reader = TemplateReader()

    def test_read_templates(self):
        templates = self.reader.readTeamplates()
        print(templates)