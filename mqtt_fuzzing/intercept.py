import ssl
import logging
import os, sys, threading, time
from mqtt_fuzzing.mqtt_ping import MQTTAlive
from mqtt_fuzzing.config import config
from scapy.contrib.mqtt import *
from mqtt_fuzzing.fuzz import fuzz
from scapy.all import PcapWriter, Ether, IP, TCP
import socket
import errno
import select
import copy


logger = logging.getLogger(__name__)
logger.setLevel('INFO')


def receive_from(s):
    # receive data from a socket until no more data is there
    b = b""
    while True:
        data = s.recv(4096)
        b += data
        if not data or len(data) < 4096:
            break
    return b


def handle_data(data, modules, dont_chain, incoming, verbose):
    # execute each active module on the data. If dont_chain is set, feed the
    # output of one plugin to the following plugin. Not every plugin will
    # necessarily modify the data, though.
    for m in modules:
        if verbose:
            print("> > > > in: " if incoming else "< < < < out: ") + m.name
        if dont_chain:
            m.execute(data)
        else:
            data = m.execute(data)
    return data


def is_client_hello(sock):
    firstbytes = sock.recv(128, socket.MSG_PEEK)
    print(firstbytes[0])
    return (len(firstbytes) >= 3 and
            firstbytes[0] == 0x16 and
            firstbytes[1:3] in [b"\x03\x00",
                                b"\x03\x01",
                                b"\x03\x02",
                                b"\x03\x03",
                                b"\x02\x00"]
            )


def enable_ssl(remote_socket, local_socket):
    local_socket = ssl.wrap_socket(local_socket,
                                   server_side=True,
                                   cert_reqs=ssl.CERT_NONE,
                                   ca_certs='data/certs/ca.crt',
                                   certfile=config['Broker']['Certfile'],
                                   keyfile=config['Broker']['Keyfile'],
                                   ssl_version=ssl.PROTOCOL_TLS,
                                   )
    remote_socket = ssl.wrap_socket(remote_socket)
    print("Enabled SSL")
    return [remote_socket, local_socket]


def starttls(local_socket, read_sockets):
    return (config['Broker'].getboolean('SSL') and
            local_socket in read_sockets and
            not isinstance(local_socket, ssl.SSLSocket)
            and is_client_hello(local_socket)
            )


class MultInterceptor(threading.Thread):
    def __init__(self, templates, in_socket, mqtt_alive, in_addrinfo, pcapwriter):
        """Initialization method of the `MultInterceptor` class.

        Parameters
        ----------
        templates : :obj:`Template`
            A `Template` dictionary that will be parsed to obtain the conditions
            and other values. The packettypes are used as keys. The templates are the values.
        """
        self.packets = dict()
        self.templates = templates
        self.pktwriter = open(config['Output']['File'], 'w')
        self.pktwriterpcap = pcapwriter
        self.pktinputwriter = open(config['Output']['Unspoofed'], 'w')
        self.seq1 = 0
        self.seq2 = 0
        self.ack1 = 0
        self.ack2 = 0
        self.in_socket = in_socket
        self.mqtt_alive = mqtt_alive
        self.client_ip = in_addrinfo[0]
        self.client_port = in_addrinfo[1]
        self.broker_ip = config['Broker']['Host']
        self.broker_port = config['Broker'].getint('Port')
        self.fuzzer_ip = '123.123.123.123' # Gets overwritten after connection to broker
        self.fuzzer_port = '12345' # Gets overwritten after connection to broker

        super().__init__()

    def modify(self, packet, to_broker):
        """This is the callback method that will be called when a packet
        is intercepted. It is responsible of executing the preconditions,
        executions and postconditions of the `Template`.

        Parameters
        ----------
        packet : :obj:`Bytes`
            The packet that is intercepted.

        """

        # Initialization of the Packet with the new raw bytes
        payload = packet

        # Determine Message Type
        original_payload = copy.deepcopy(payload)
        print("Original Payload {}".format(payload))

        work_packet = MQTT(packet)

        work_packet = fuzz(work_packet, to_broker, self.templates)

        return bytes(work_packet)

    running = True

    def run(self):
        local_socket = self.in_socket
        remote_socket = socket.socket()

        try:
            remote_socket.connect((config['Broker']['Host'], config['Broker'].getint('Port')))
            print('Connected to {}:{}'.format(config['Broker']['Host'], config['Broker']['Port']))
            self.fuzzer_ip, self.fuzzer_port = remote_socket.getsockname()
            #if config['Broker']['SSL']:
            #    remote_socket = ssl.wrap_socket(remote_socket)
        except socket.error as serr:
            if serr.errno == errno.ECONNREFUSED:
                print('Connection refused to {}:{}'.format(config['Broker']['Host'], config['Broker']['Port']))
            raise serr

        # This loop ends when no more data is received on either the local or the
        # remote socket
        timer = 0.
        while self.running:
            # Read from any of the sockets timout after 1s
            try:
                read_sockets, _, _ = select.select([remote_socket, local_socket], [], [], float(config['Heartbeat']['Frequency']))
            except ValueError:
                # filedescriptor out of range in select()
                self.stop()
                break
            timer += float(config['Heartbeat']['Frequency'])
            if timer > config['Heartbeat'].getint('Timeout'):
                print("Client is not sending data anymore! Bug detected!")
                self.mqtt_alive.stop()
            if starttls(local_socket, read_sockets):
                print("Enable SSL")
                try:
                    ssl_sockets = enable_ssl(remote_socket, local_socket)
                    remote_socket, local_socket = ssl_sockets
                    print("SSL enabled")
                except ssl.SSLError as e:
                    print("SSL handshake failed", str(e))
                    break

                read_sockets, _, _ = select.select(ssl_sockets, [], [], float(config['Heartbeat']['Frequency']))

            for sock in read_sockets:
                try:
                    peer = sock.getpeername()
                    data = receive_from(sock)
                    print('Received {} bytes'.format(len(data)))

                    if sock == local_socket:
                        timer = 0
                        # From Client
                        self.write_packet(data, modified=False, to_broker=True)
                        if len(data):
                            data = self.modify(data, True)
                            print("Sending data to broker: {}\n\n".format(data))
                            remote_socket.send(data)
                            self.write_packet(data, modified=True, to_broker=True)
                        else:
                            print("Connection from local client {} closed".format(peer))
                            self.stop()
                            break
                    elif sock == remote_socket:
                        # From Broker
                        self.write_packet(data, modified=False, to_broker=False)
                        if len(data):
                            data = self.modify(data, False)
                            print("Sending data to client: {}\n\n".format(data))
                            local_socket.send(data)
                            self.write_packet(data, modified=True, to_broker=False)
                        else:
                            print("Connection to broker {} closed".format(peer))
                            self.stop()
                            break
                except OSError:
                    # Socket was closed in the meantime
                    remote_socket.close()
                    local_socket.close()
                    self.running = False
                    break

    def write_packet(self, packet, modified, to_broker):
        p = MQTT(packet).show2(dump=True, indent=0)
        info = "\n\nTime: {}\nTo Broker: {} \n".format(time.time(), to_broker)
        if to_broker and modified:
            src_ip = self.fuzzer_ip
            src_port = self.fuzzer_port
            dst_ip = self.broker_ip
            dst_port = self.broker_port
            seq = self.seq1
            ack = self.ack1
        elif to_broker and not modified:
            src_ip = self.client_ip
            src_port = self.client_port
            dst_ip = self.fuzzer_ip
            dst_port = self.broker_port
            seq = self.seq2
            ack = self.ack2
        elif not to_broker and modified:
            src_ip = self.fuzzer_ip
            src_port = self.broker_port
            dst_ip = self.client_ip
            dst_port = self.client_port
            seq = self.seq2
            ack = self.ack2
        elif not to_broker and not modified:
            src_ip = self.broker_ip
            src_port = self.broker_port
            dst_ip = self.fuzzer_ip
            dst_port = self.fuzzer_port
            seq = self.seq1
            ack = self.ack1

        if modified:
            self.pktwriter.write(info)
            self.pktwriter.write(p)
        else:
            self.pktinputwriter.write(info)
            self.pktinputwriter.write(p)
        self.pktwriterpcap.write(
            Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, seq=seq, flags='PA', ack=seq) / packet)

        # increase seq number
        if to_broker and modified:
            self.ack1 = self.seq1
            self.seq1 += len(packet) % pow(2, 32)
        elif to_broker and not modified:
            self.ack2 = self.seq2
            self.seq2 += len(packet) % pow(2, 32)
        elif not to_broker and modified:
            self.ack2 = self.seq2
            self.seq2 += len(packet) % pow(2, 32)
        elif not to_broker and not modified:
            self.ack1 = self.seq1
            self.seq1 += len(packet) % pow(2, 32)

    def stop(self):
        self.running = False
        self.in_socket.close()
        self.pktwriter.close()
        self.pktinputwriter.close()

class ConnectionHandler(threading.Thread):
    templates = {}
    pcapw = PcapWriter(config['Output']['FilePcap'])

    def set_templates(self, templates):
        self.templates = templates

    def run(self):
        # This method is executed in a thread. It will relay data between the local
        # host and the remote host, while letting modules work on the data before
        # passing it on.

        # this is the socket we will listen on for incoming connections
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # print("Setting second ip to Broker IP")
        # p = subprocess.Popen(['ip', 'addr', 'add', config['Broker']['Host'] + '/' + config['Broker']['Mask'], 'dev',
        #                  config['Fuzzer']['Interface']])
        # p.wait()
        print("Binding to Port")
        try:
            proxy_socket.bind(('', config['Broker'].getint('Port')))
        except socket.error as e:
            print(e.strerror)
            sys.exit(5)

        # Listens for up to 10 connections
        proxy_socket.listen(10)

        print("Intercepting for {} seconds".format(config['Fuzzer'].getint('Total')))

        alive = MQTTAlive(config['Fuzzer'].getint('Total'))
        alive.start()
        while alive.is_alive():
            print('Waiting for connection')
            proxy_socket.settimeout(1.)
            timeout = True
            while alive.is_alive() and timeout:
                timeout = False
                try:
                    in_socket, in_addrinfo = proxy_socket.accept()
                except socket.timeout:
                    timeout = True
            if not timeout:
                print('Connection from {}'.format(in_addrinfo))
                proxy_thread = MultInterceptor(self.templates, in_socket, alive, in_addrinfo, self.pcapw)
                proxy_thread.start()
                alive.add_thread(proxy_thread)

        self.pcapw.close()