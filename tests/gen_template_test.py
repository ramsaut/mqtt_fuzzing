import unittest
from mqtt_fuzzing.config import config
import logging
from mqtt_fuzzing.gen_template import *

logger = logging.getLogger(__name__)
logger.setLevel('INFO')

@unittest.skip
class TestSpoofing(unittest.TestCase):
    backend = FuzzingBackend()

    def test_start_spoofing(self):

        self.assertTrue(self.backend.start_spoofing(config['Device']['Host'],
                                       config['Broker']['Host'],
                                       config['Fuzzer']['Interface']))

    def test_stop_spoofing(self):
        self.backend.stop_spoofing()


class TestCapture(unittest.TestCase):
    backend = FuzzingBackend()

    def test_read_capture(self):
        self.backend.read_capture(config['Fuzzer']['MQTT_Sample'], config['Fuzzer']['Filter'])
        self.assertIsNotNone(self.backend.templates)

    def tearDown(self):
        self.backend.templates._tgen.__del__()


class TestDissection(unittest.TestCase):
    backend = FuzzingBackend()

    def setUp(self):
        self.backend.read_capture(config['Fuzzer']['MQTT_Sample'], config['Fuzzer']['Filter'])
        self.assertIsNotNone(self.backend.templates)

    def test_dissection(self):
        self.backend.dissect()

    def test_choose_template(self):
        self.backend.choose_template(5)
        self.assertEqual(self.backend.current_template.getlayer("RAW.MQTT")['msg'].value, 'hello world #3916')

    def tearDown(self):
        self.backend.templates._tgen.__del__()


class TestWrite(unittest.TestCase):
    backend = FuzzingBackend()

    def setUp(self):
        self.backend.read_capture(config['Fuzzer']['MQTT_Sample'], config['Fuzzer']['Filter'])
        self.assertIsNotNone(self.backend.templates)
        self.backend.dissect()

    def test_write_template(self):
        self.backend.templates.write('data/templates')

    def test_write_by_packet_type(self):
        self.backend.write_by_packet_type('data/templates')

    def tearDown(self):
        self.backend.templates._tgen.__del__()

@unittest.skip
class TestWireshark(unittest.TestCase):
    backend = FuzzingBackend()

    def setUp(self):
        self.backend.read_capture(config['Fuzzer']['MQTT_Sample'], config['Fuzzer']['Filter'])
        self.assertIsNotNone(self.backend.templates)

    def test_wireshark(self):
        self.backend.wireshark()


if __name__ == '__main__':
    unittest.main()
