import logging

logger = logging.getLogger(__name__)
logger.setLevel('INFO')


# Preconditions

# Log new packet
def logging(packet):
    print("New packet: {}".format(packet))
    return packet

# The first precondition, global_vars, is creating a global variable that will remain constant for all intercepted
# packets. It will be used to store all the test cases that we will use to fuzz the packets.
def global_vars(packet):
    try:
        packet.fuzz_cases
    except AttributeError:
        setattr(packet, 'fuzz_cases', [])
    return packet

