import paho.mqtt.client as paho
from mqtt_fuzzing.config import config
import threading
import time
import os
import signal


class MQTTAlive(threading.Thread):
    last_beat = time.time()
    client1 = paho.Client("heartbeatsub")
    client2 = paho.Client("heartbeatpub")

    def __init__(self, interceptor, timeout):
        super().__init__()
        self.timeout = timeout
        self.interceptor = interceptor
        self.client1.connect(config['Broker']['Host'], int(config['Broker']['Port'])) #establish connection
        self.client1.on_connect = self.on_connect
        self.client1.on_message = self.on_message
        self.client2.connect(config['Broker']['Host'], int(config['Broker']['Port']))  # establish connection

    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code " + str(rc))
        client.subscribe("heartbeat")

    def on_message(self, client, userdata, msg):
        self.last_beat = time.time()

    def run(self):
        self.last_beat = time.time()
        starttime = time.time()
        while time.time() - starttime < self.timeout:
            self.client1.loop(timeout=0.3, max_packets=1)
            self.client2.publish("heartbeat")
            # Timeout after 2 seconds
            if time.time() - self.last_beat > 2:
                print("Timeout! {} {} Stopping execution".format(time.time(),self.last_beat))
                self.interceptor.terminate()
                return
        print("Finished test without finding bugs. Quitting!")
        self.interceptor.terminate()
