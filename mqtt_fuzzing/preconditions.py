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


def track_tcpip(packet, tcp_variables):
    from scapy.all import IP
    from mqtt_fuzzing.config import config
    # Global vars for tracking the seq numbers

    scapy_pkt = IP(packet)
    # Saving the seq numbers state for each packet
    if scapy_pkt['TCP'].sport == int(config['Broker']['Port']):
        tcp_variables['sseq'] = scapy_pkt['TCP'].seq
        tcp_variables['sack'] = scapy_pkt['TCP'].ack
        # 20 is IP header length
        tcp_variables['snextseq'] = scapy_pkt['TCP'].seq + scapy_pkt['IP'].len - 20 - len(scapy_pkt['TCP'])
        print("From Broker: Seq {} ACK {} Next {}".format(tcp_variables['sseq'], tcp_variables['sack'], tcp_variables['snextseq']))
    elif scapy_pkt['TCP'].dport == int(config['Broker']['Port']):
        tcp_variables['dseq'] = scapy_pkt['TCP'].seq
        tcp_variables['dack'] = scapy_pkt['TCP'].ack
        # 20 is IP header length
        tcp_variables['dnextseq'] = scapy_pkt['TCP'].seq + scapy_pkt['IP'].len - 20 - len(scapy_pkt['TCP'])
        print("To Broker  : Seq {} ACK {} Next {}".format(tcp_variables['dseq'], tcp_variables['dack'],
                                                          tcp_variables['dnextseq']))
    return tcp_variables
