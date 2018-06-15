import paho.mqtt.client as paho
from mqtt_fuzzing.config import config
import threading
import time

class MQTTAlive(threading.Thread):
    last_beat = time.time()

    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code " + str(rc))
        client.subscribe("heartbeat")

    def on_message(self, client, userdata, msg):
        self.last_beat = time.time()


    def __init__(self):
        super().__init__()
        client1 = paho.Client("heartbeatsub")                           #create client object                         #assign function to callback
        client1.connect(config['Broker']['Host'], int(config['Broker']['Port'])) #establish connection
        client1.on_connect = self.on_connect
        client1.on_message = self.on_message
        client1.subscribe("heartbeat")
        client2 = paho.Client("heartbeatpub")
        client2.connect(config['Broker']['Host'], int(config['Broker']['Port']))  # establish connection
        while True:
            client1.loop(timeout=1.0, max_packets=1)
            client2.publish("heartbeat")
            # Timeout after 5 seconds
            if time.time() - self.last_beat > 5:
                print("Timeout! Stopping execution")
                break


