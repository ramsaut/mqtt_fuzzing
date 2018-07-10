from mqtt_fuzzing.config import config
import copy
from scapy.sendrecv import sniff
import json
import binascii
from mqtt_fuzzing.utils import *

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

