def insert_tcpip(packet, tcp_variables):
    from scapy.all import IP
    from mqtt_fuzzing.config import config
    # Global vars for tracking the seq numbers

    scapy_pkt = IP(packet.get_payload())
    print(tcp_variables)
    print("TCP: {} SPort: {} DPort: {}".format(tcp_variables, scapy_pkt['TCP'].sport, scapy_pkt['TCP'].dport))
    # TCP/IP session simulation is required
    if scapy_pkt['TCP'].sport == int(config['Broker']['Port']):
        try:
            scapy_pkt['TCP'].seq = tcp_variables['dack']
            scapy_pkt['TCP'].ack = tcp_variables['dnextseq']
        except KeyError:
            print("First packet, SEQ / ACKs not known yet, originals will remain")
    elif scapy_pkt['TCP'].dport == int(config['Broker']['Port']):
        try:
            scapy_pkt['TCP'].seq = tcp_variables['sack']
            scapy_pkt['TCP'].ack = tcp_variables['snextseq']
        except KeyError:
            print("First packet, SEQ / ACKs not known yet, originals will remain")
    # Recalculating the control fields of the pkt
    del scapy_pkt['IP'].chksum
    del scapy_pkt['TCP'].chksum
    # Forward the packet
    packet.set_payload(bytes(scapy_pkt))
    return packet

def mqtt_len_rec(packet):
    packet['RAW.MQTT']['len'] = packet['RAW.MQTT']['topic_len'] + 2 + len(packet['RAW.MQTT']['msg'])
    return packet
