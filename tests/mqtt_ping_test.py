import unittest
from mqtt_fuzzing.mqtt_ping import MQTTAlive

class MQTTAliveTest(unittest.TestCase):

    def test_heartbeat(self):
        MQTTAlive()