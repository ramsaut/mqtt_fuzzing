import polymorph
from polymorph.utils import capture, get_arpspoofer, set_ip_forwarding
from os.path import dirname, join
import os
import logging
import pathlib
from polymorph.interceptor import Interceptor
from polymorph.packet import Packet
import mqtt_fuzzing.preconditions
from polymorph.template import Template
import os, sys, threading, time
from mqtt_fuzzing.mqtt_ping import MQTTAlive
import multiprocessing

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


class MultInterceptor(Interceptor, multiprocessing.Process):
    def __init__(self, templates_path,
                 iptables_rule="iptables -A FORWARD -j NFQUEUE --queue-num 1",
                 ip6tables_rule="ip6tables -A FORWARD -j NFQUEUE --queue-num 1"):
        """Initialization method of the `MultInterceptor` class.

        Parameters
        ----------
        templates : :obj:`Template`
            A `Template` dictionary that will be parsed to obtain the conditions
            and other values. The packettypes are used as keys. The templates are the values.
        iptables_rule : :obj:`str`
            Iptables rule for intercepting packets.
        ip6tables_rule : :obj:`str`
            Iptables rule for intercepting packets for ipv6.

        """
        multiprocessing.Process.__init__(self)
        self.iptables_rule = iptables_rule
        self.ip6tables_rule = ip6tables_rule
        self.packets = dict()
        self.read_templates_from_path(templates_path)

        self._preconditions = [mqtt_fuzzing.preconditions.logging, mqtt_fuzzing.preconditions.global_vars]
        self._executions = []
        self._postconditions = []
        self._functions = [self._preconditions,
                           self._executions,
                           self._postconditions]

    def read_templates_from_path(self, path):
        for direc in os.walk(path):
            for file in direc[2]:
                t = Template(from_path=os.path.join(direc[0], file))
                msgtype = t.getlayer('RAW.MQTT').getfield('msgtype').dict()['frepr']
                self.packets[msgtype] = Packet(t)


    def linux_modify(self, packet):
        """This is the callback method that will be called when a packet
        is intercepted. It is responsible of executing the preconditions,
        executions and postconditions of the `Template`.

        Parameters
        ----------
        packet : :obj:`Packet`
            Netfilterqueue packet object. The packet that is intercepted.

        """

        # Initialization of the Packet with the new raw bytes
        payload = packet.get_payload()
        tcp_header_length = (payload[0x20] & 0xf0) >> 4
        if tcp_header_length == 5 and len(payload) > 0x28:
            message_type = (payload[0x28] & 0xf0) >> 4
            print(message_type)
        else:
            # check if ack
            if len(payload) == 40 and (payload[0x21] & 0x10) >> 4:
                packet.accept()
                return
            print("other length {} or packet to short {}".format(tcp_header_length, len(payload)))
            packet.accept()
            return
        try:
            work_packet = self.packets[message_type]
        # No template exists
        except KeyError:
            packet.accept()
            return

        work_packet.raw = payload

        # Executing the preconditions, executions and postconditions
        for functions in self._functions:
            for condition in functions:
                pkt = condition(work_packet)
                # If the condition returns None, it is not held and the
                # packet must be forwarded
                if pkt is None:
                    if work_packet:
                        packet.set_payload(work_packet.raw)
                    packet.accept()
                    return
                # If the precondition returns the packet, we assign it to the
                # actual packet
                work_packet = pkt
        # If all the conditions are met, we assign the payload of the modified
        # packet to the nfqueue packet and forward it
        packet.set_payload(work_packet.raw)
        packet.accept()

    def run(self):
        self.intercept()

    def intercept(self):
        """This method intercepts the packets and send them to a callback
        function."""
        from netfilterqueue import NetfilterQueue
        nfqueue = NetfilterQueue()
        # The iptables rule queue number by default is 1
        nfqueue.bind(1, self.linux_modify)
        try:
            self.set_iptables_rules()
            print("[*] Waiting for packets...\n\n(Press Ctrl-C to exit)\n")
            nfqueue.run()
        except KeyboardInterrupt:
            self.clean_iptables()
