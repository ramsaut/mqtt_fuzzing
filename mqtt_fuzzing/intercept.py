import ssl
import logging
from polymorph.utils import capture, get_arpspoofer, set_ip_forwarding
from polymorph.interceptor import Interceptor
from polymorph.packet import Packet
import mqtt_fuzzing.preconditions
from mqtt_fuzzing.extended_template import FuzzingTemplate
from polymorph.template import Template
import os, sys, threading, time
from mqtt_fuzzing.mqtt_ping import MQTTAlive
from scapy.utils import PcapWriter
from mqtt_fuzzing.config import config
from scapy.all import Ether, IP, TCP
from scapy.contrib.mqtt import *
from mqtt_fuzzing.fuzz import fuzz
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
    return (len(firstbytes) >= 3 and
            firstbytes[0] == "\x16" and
            firstbytes[1:3] in ["\x03\x00",
                                "\x03\x01",
                                "\x03\x02",
                                "\x03\x03",
                                "\x02\x00"]
            )


def enable_ssl(remote_socket, local_socket):
    local_socket = ssl.wrap_socket(local_socket,
                                   server_side=True,
                                   certfile="mitm.pem",
                                   keyfile="mitm.pem",
                                   ssl_version=ssl.PROTOCOL_TLS,
                                   )

    remote_socket = ssl.wrap_socket(remote_socket)
    return [remote_socket, local_socket]


def starttls(local_socket, read_sockets):
    return (config['Broker'].getboolean('SSL') and
            local_socket in read_sockets and
            not isinstance(local_socket, ssl.SSLSocket) and
            is_client_hello(local_socket)
            )


class Spoofer():
    def __init__(self, targets, gateway, interface):
        self.poisener = get_arpspoofer(targets, gateway, interface)

    def start_spoofing(self):
        # set_ip_forwarding(1)
        try:
            logger.info("Started ARP-Spoofing")
            self.poisener.start()
            return True
        except Exception as e:
            print(str(e))
            logger.error("Invalid target(s) or gateway")
            # set_ip_forwarding(0)
            return False

    def stop_spoofing(self):
        self.poisener.stop()


class MultInterceptor(threading.Thread):
    def __init__(self, templates, in_socket):
        """Initialization method of the `MultInterceptor` class.

        Parameters
        ----------
        templates : :obj:`Template`
            A `Template` dictionary that will be parsed to obtain the conditions
            and other values. The packettypes are used as keys. The templates are the values.
        """
        self.packets = dict()
        self.templates = templates
        self.pktwriter = PcapWriter(config['Output']['File'], append=False, sync=True)
        self.pktinputwriter = PcapWriter(config['Output']['Unspoofed'], append=False, sync=True)
        self.in_socket = in_socket
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

        print(work_packet.summary())
        print(bytes(work_packet))
        return bytes(work_packet)

    running = True

    def run(self):
        local_socket = self.in_socket
        remote_socket = socket.socket()

        try:
            remote_socket.connect((config['Broker']['Host'], config['Broker'].getint('Port')))
            print('Connected to {}:{}'.format(config['Broker']['Host'], config['Broker']['Port']))
        except socket.error as serr:
            if serr.errno == errno.ECONNREFUSED:
                print('Connection refused to {}:{}'.format(config['Broker']['Host'], config['Broker']['Port']))
            raise serr

        # This loop ends when no more data is received on either the local or the
        # remote socket
        while self.running:
            read_sockets, _, _ = select.select([remote_socket, local_socket], [], [], 1)

            if starttls(local_socket, read_sockets):
                try:
                    ssl_sockets = enable_ssl(remote_socket, local_socket)
                    remote_socket, local_socket = ssl_sockets
                    print("SSL enabled")
                except ssl.SSLError as e:
                    print("SSL handshake failed", str(e))
                    break

                read_sockets, _, _ = select.select(ssl_sockets, [], [])

            for sock in read_sockets:
                peer = sock.getpeername()
                data = receive_from(sock)
                print('Received {} bytes'.format(len(data)))

                if sock == local_socket:
                    # From Client
                    if len(data):
                        print(data)
                        data = self.modify(data, True)
                        print("Sending data to client: {}".format(data))
                        remote_socket.send(data)
                    else:
                        print("Connection from local client {} closed".format(peer))
                        remote_socket.close()
                        running = False
                        break
                elif sock == remote_socket:
                    # From Broker
                    if len(data):
                        print(data)
                        data = self.modify(data, False)
                        print("Sending data to broker: {}".format(data))
                        local_socket.send(data)
                    else:
                        print("Connection to broker {} closed".format(peer))
                        local_socket.close()
                        running = False
                        break

    def write_netfilterqueue_packet(self, packet, original_payload, raw=None):
        if raw is None:
            raw = packet.get_payload()
        # Format hw adress in the format ff:ff:ff:ff:ff:ff
        asadress = ':'.join(packet.get_hw().hex()[i:i + 2] for i in range(0, 12, 2))
        # asadress = "ff:ff:ff:ff:ff:ff"
        self.pktwriter.write(Ether(dst=asadress) / IP(raw))
        self.pktinputwriter.write(Ether(dst=asadress) / IP(original_payload))

    def stop(self):
        self.running = False
        self.in_socket.close()


class ConnectionHandler(threading.Thread):
    templates = {}

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
                proxy_thread = MultInterceptor(self.templates, in_socket)
                proxy_thread.start()
                alive.add_thread(proxy_thread)
