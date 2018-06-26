import collections
import time
from scapy.utils import wrpcap
from mqtt_fuzzing.config import config

class Tracker():
    packets = collections.deque()

    def addPacket(self, packet):
        self.removeOutdatedPackets()
        self.packets.append((time.time(), packet))
        print("Appended packet; new length: {}".format(len(self.packets)))

    def removeOutdatedPackets(self):
        now = time.time()
        oldestPacket = None
        try:
            oldestPacket = self.packets.popleft()
            while (now - oldestPacket[0]) > int(config['Output']['BufferTime']):
                print("Removing packet Now: {} OldestPacket: {} Diff: {}, BufferTime: {}".format(
                    now, oldestPacket[0], now-oldestPacket, int(config['Output']['BufferTime'])))
                oldestPacket = self.packets.popleft()
        except IndexError:
            # If no elements are present
            pass
        if oldestPacket is not None:
            self.packets.appendleft(oldestPacket)

    def writeToPCAP(self):
        print("Writing {} packets to {}".format(len(self.packets), config['Output']['File']))
        self.removeOutdatedPackets()
        while True:
            try:
                _, packet = self.packets.popleft()
            except IndexError:
                # When all packets are written
                break
            wrpcap(config['Output']['File'], packet, append=True)
