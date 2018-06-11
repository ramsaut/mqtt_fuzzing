import polymorph
from polymorph.utils import capture, get_arpspoofer, set_ip_forwarding
from os.path import dirname, join
import os
import logging
import pathlib

logger = logging.getLogger(__name__)
logger.setLevel('INFO')

class FuzzingBackend:
    poisener = None
    templates = None
    current_template = None

    def start_spoofing(self, targets, gateway, interface):
        set_ip_forwarding(1)
        try:
            logger.info("Started ARP-Spoofing between {} and {} on interface {}".format(targets, gateway, interface))
            self.poisener = get_arpspoofer(targets, gateway, interface)
            self.poisener.start()
            return True
        except Exception as e:
            print(str(e))
            logger.error("Invalid target(s) or gateway")
            set_ip_forwarding(0)
            return False

    def stop_spoofing(self):
        self.poisener.stop()

    def read_capture(self, file, filter):
        self.templates = capture(userfilter=filter,
                func=self.log_packet,
                offline=file)

    def dissect(self):
        logger.info("Dissecting packets")
        self.templates[-1]
        logger.info("Finished dissecting packets")

    def wireshark(self):
        polym_path = dirname(polymorph.__file__)
        os.system("nohup wireshark %s &" % join(polym_path, ".tmp.pcap"))

    def choose_template(self, id):
        self.current_template = self.templates[id+1] # The first template has id 1 not 0

    def write_by_packet_type(self, path):
        for template in self.templates:
            self.save_by_field(template, path, "RAW.MQTT", "msgtype")

    def save_by_field(self, template, path, layer, field):
        l = template.getlayer(layer)
        if l is None:
            logger.debug("Template {} does not have layer {}".format(template, layer))
            return
        f = l.getfield(field)
        if f is None:
            logger.debug("Layer {} does not have field {}".format(layer, f))
            return
        repr = f.frepr

        dir = os.path.join(path, str(repr))
        pathlib.Path(dir).mkdir(exist_ok=True)
        template.add_precondition("log", self.log_packet)
        template.write(os.path.join(dir, "template.json"))

    @staticmethod
    def log_packet(packet):
        logger.info(packet.summary())
        return packet