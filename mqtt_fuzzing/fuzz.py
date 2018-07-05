from scapy.all import IP, TCP, Ether
from subprocess import Popen, PIPE, STDOUT
from mqtt_fuzzing.utils import goc, add_packet_to_templates
import traceback

def fuzz(packet, to_broker, templates):
    payload = packet
    been_fuzzed = set()
    while payload:
        try:
            layer = templates[(to_broker, type(payload).__name__)]
        except KeyError:
            # If there is no template return original
            return packet
        print(layer)

        for fieldname, value in payload.fields.items():
            template_field = layer['fields'][fieldname]
            pastvalues = template_field['values']

            fuzzing = template_field['fuzzing']
            if fuzzing:
                print(fuzzing)
                if fuzzing['fuzzer'] == 'radamsa':
                    if fuzzing['cases'] == 'packet':
                        been_fuzzed.add((type(payload).__name__, fieldname))
                        content = value
                        print("Content: {}".format(content))
                        p = Popen(['radamsa'], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                        fuzzed_case = p.communicate(input=content)[0]
                        print("Fuzzed: {}".format(fuzzed_case))
                        payload.fields[fieldname] = fuzzed_case

        payload = payload.payload





    # if not packet.fuzz_cases:
    #     valid_cases = "valid_cases"
    #     dpath = "fuzz_cases"
    #     subprocess.check_call(["radamsa",
    #                            "-o",
    #                            join(dpath, "fuzz-%n.%s"),
    #                            "-n",
    #                            "58",
    #                            "-r",
    #                            valid_cases])
    #     packet.fuzz_cases = [open(join(dpath, f), 'rb').read()
    #                   for f in listdir(dpath)]
    # # Inserting the value and recalculating some fields
    print("Fuzzed packet. Recalculating values")
    print(been_fuzzed)

    # Recompute if values have not been fuzzed
    if ('MQTT', 'len') not in been_fuzzed:
        del packet['MQTT'].len
    if 'MQTTPublish' in packet:
        if ('MQTTPublish', 'length') not in been_fuzzed:
            del packet['MQTTPublish'].length
    if 'MQTTConnect' in packet:
        if ('MQTTConnect', 'length') not in been_fuzzed:
            del packet['MQTTConnect'].length
        if ('MQTTConnect', 'clientIdlen') not in been_fuzzed:
            del packet['MQTTConnect'].clientIdlen

    try:
        print(bytes(packet))
        packet.show()
    except Exception as e:
        print(packet.type)
        traceback.print_exc()
        print("Payload could not be created. Maybe string longer than possible? Retrying...")
        packet.show()
        #packet = fuzz(packet, to_broker, templates)
    return packet