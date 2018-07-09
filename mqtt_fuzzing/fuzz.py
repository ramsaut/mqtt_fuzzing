from scapy.all import IP, TCP, Ether
from subprocess import Popen, PIPE, STDOUT
from mqtt_fuzzing.utils import goc, add_packet_to_templates
import traceback
import random

def fuzz(packet, to_broker, templates):
    original = packet.copy()
    payload = packet
    possible_fuzzing = set()
    layers = {}
    while payload:
        try:
            layer = templates[(to_broker, type(payload).__name__)]
        except KeyError:
            # If there is no template continue with next layer
            continue
        layers[type(payload).__name__] = payload
        # Clean cache so values get recalculated
        payload.raw_packet_cache = None

        for fieldname, value in payload.fields.items():
            template_field = layer['fields'][fieldname]
            fuzzing = template_field['fuzzing']
            if fuzzing and fuzzing['fuzzer'] is not None:
                possible_fuzzing.add((type(payload).__name__, fieldname))
        payload = payload.payload

    if len(possible_fuzzing) == 0:
        return original

    layername, fieldname = random.choice(list(possible_fuzzing))
    template_field = templates[(to_broker, layername)]['fields'][fieldname]
    fuzzing = template_field['fuzzing']
    pastvalues = template_field['values']
    been_fuzzed = (layername, fieldname)
    print("Fuzzing: {} {}".format(layername, fieldname))
    if fuzzing['fuzzer'] == 'radamsa':
        if fuzzing['cases'] == 'packet':
            content = layers[layername].fields[fieldname]
            print("Content: {}".format(content))
            p = Popen(['radamsa'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
            fuzzed_case = p.communicate(input=content)[0]
            print("Fuzzed: {}".format(fuzzed_case))
            layers[layername].fields[fieldname] = fuzzed_case
    if fuzzing['fuzzer'] == 'scapy':
        fuzzed_case = layers[layername].fieldtype[fieldname].randval() + 0
        print("Fuzzed: {}".format(fuzzed_case))
        layers[layername].fields[fieldname] = fuzzed_case

    mqtt_recalculate(been_fuzzed, packet)
    try:
        bytes(packet)
        packet.show()
    except Exception as e:
        print(packet.type)
        traceback.print_exc()
        print("Payload could not be created. Maybe string longer than possible? Retrying...")
        packet.show()
        packet = fuzz(original, to_broker, templates)
    return packet


def mqtt_recalculate(been_fuzzed, packet):
    print("Fuzzed packet. Recalculating values")
    # Recompute if values have not been fuzzed
    if ('MQTT', 'len') != been_fuzzed:
        del packet['MQTT'].len
    if 'MQTTPublish' in packet:
        if ('MQTTPublish', 'length') != been_fuzzed:
            del packet['MQTTPublish'].length
    if 'MQTTConnect' in packet:
        if ('MQTTConnect', 'length') != been_fuzzed:
            del packet['MQTTConnect'].length
        if ('MQTTConnect', 'clientIdlen') != been_fuzzed:
            del packet['MQTTConnect'].clientIdlen
