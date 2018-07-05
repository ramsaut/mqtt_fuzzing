import paho.mqtt.client as paho
from mqtt_fuzzing.config import config
import threading
import time
import os
import signal
import ssl


class MQTTAlive(threading.Thread):
    last_beat = time.time()
    client1 = paho.Client("heartbeatsub")
    client2 = paho.Client("heartbeatpub")
    threads = []
    running = True

    def __init__(self, timeout):
        super().__init__()
        if config['Broker'].getboolean('SSL'):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.client1.tls_set_context(context)
            self.client2.tls_set_context(context)

        self.timeout = timeout
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
        while time.time() - starttime < self.timeout and self.running:
            self.client1.loop(timeout=float(config['Heartbeat']['Frequency']), max_packets=1)
            # print("Send heartbeat {}".format(float(config['Heartbeat']['Frequency'])))
            time.sleep(float(config['Heartbeat']['Frequency']))
            self.client2.publish("heartbeat")
            # Timeout after 2 seconds
            if time.time() - self.last_beat > float(config['Heartbeat']['Timeout']):
                print("Timeout! {} {} Stopping execution".format(time.time(), self.last_beat))
                self.stop()
                return
        if self.running:
            print("Finished test without finding bugs. Quitting!")
        self.stop()

    def add_thread(self, t):
        self.threads.append(t)

    def stop(self):
        for t in self.threads:
            t.stop()
        self.running = False