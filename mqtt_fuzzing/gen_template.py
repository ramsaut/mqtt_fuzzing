import polymorph
from polymorph.utils import capture, get_arpspoofer, set_ip_forwarding
from os.path import dirname, join
import os
import logging
import pathlib
from polymorph.interceptor import Interceptor
from polymorph.packet import Packet
import mqtt_fuzzing.preconditions
from mqtt_fuzzing.extended_template import FuzzingTemplate
from polymorph.template import Template
import os, sys, threading, time
from mqtt_fuzzing.mqtt_ping import MQTTAlive
import multiprocessing
from scapy.utils import wrpcap
from scapy.utils import PcapWriter
from mqtt_fuzzing.config import config
from scapy.all import Ether, IP
from mqtt_fuzzing.extended_template import write_template
from mqtt_fuzzing.postcondition import insert_tcpip
from mqtt_fuzzing.preconditions import track_tcpip
import socket
import errno
import select
import copy
from scapy.sendrecv import sniff
import json
import binascii
from mqtt_fuzzing.utils import *
from mqtt_fuzzing.fuzz import fuzz

logger = logging.getLogger(__name__)
logger.setLevel('INFO')

class FuzzingBackend:
    poisener = None
    templates = None
    current_template = None

    def start_spoofing(self, targets, gateway, interface):
        # set_ip_forwarding(1)
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
        write_template(template, os.path.join(dir, "template.json"))

    @staticmethod
    def log_packet(packet):
        logger.info(packet.summary())
        return packet

class TemplateGenerator():

    def read_capture(self):
        plist = sniff(filter=config['Fuzzer']['Filter'], prn=self.log_packet, offline=config['Fuzzer']['MQTT_Sample'])
        return plist

    def create_templates(self, packets):
        templates = {}
        while len(packets):
            packet = packets.pop(0)
            print(packet.summary())
            # Strip Ether, IP, TCP
            payload = packet.getlayer(3)
            to_broker = packet['TCP'].dport == int(config['Broker']['Port'])
            add_packet_to_templates(templates, to_broker, payload)

        print(templates)
        return templates

    def save_to_disk(self, templates):
        templates_new = []
        for key, value in templates.items():
            template = {
                'to_broker': key[0],
                'name': key[1],
                'attributes': value
            }
            templates_new.append(template)

        with open(config['Output']['Templates'], 'w') as outfile:
            json.dump(templates_new, outfile, indent = 4, cls=OwnEncoder)

    @staticmethod
    def log_packet(packet):
        # logger.info(packet.summary())
        return packet

class OwnEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return binascii.hexlify(obj).decode('utf-8')
        return json.JSONEncoder.default(self, obj)

class TemplateReader():

    def readTeamplates(self):
        with open(config['Fuzzer']['Templates'], 'r') as infile:
            templates = json.load(infile)

        templates_new = {}
        for template in templates:
            templates_new[(template['to_broker'], template['name'])] = template['attributes']
            for name, field in template['attributes']['fields'].items():
                field['values'] = set(field['values'])

        return templates_new

