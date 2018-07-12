# mqtt_fuzzing

## Installation
### Radamsa
https://github.com/aoh/radamsa

Nutshell:

```bash
 $ sudo apt-get install gcc make git wget
 $ git clone https://github.com/aoh/radamsa.git && cd radamsa && make && sudo make install
 $ echo "HAL 9000" | radamsa
```
### Requirements
Setup python virtualenv with pip.
Activate the environment.
Install python requirements by executing:
```bash
pip install -r requirements.txt
```

## Configuration
The fuzzer can be configured in the config.ini file.
If the fuzzer shall be configured by external programs the dict in mqtt_fuzzing.config.config needs to be overwritten e.g. using the read_json method.

## Generate Template
The templates can be generated using the following code:
```python
class TestGenerator():
    generator = TemplateGenerator()

    def test_create_templates(self):
        list = self.generator.read_capture()
        templates = self.generator.create_templates(list)
        self.generator.save_to_disk(templates)
```
A generator is setup using `TemplateGenerator()`.
A list of packages is read in from the file specified in `config['Fuzzer']['MQTT_Sample']` using the method `self.generator.read_capture()`.
Templates are generated using `self.generator.create_templates(list)` and written to disk using `self.generator.save_to_disk(templates)`

## Understand and Modify templates
For each layer (above TCP) a template is generated. The name of the layer and the direction of the packet (towards the broker or from the broker) is saved.
Furthermore for each field in the layer the values which occured and the type of the field are saved. An empty fuzzing dict in included.
```json
{
        "to_broker": true,
        "name": "MQTT",
        "attributes": {
            "fields": {
                "type": {
                    "values": [
                        0,
                        ...
                        14
                    ],
                    "type": "BitEnumField",
                    "fuzzing": {
                        "fuzzer": null,
                        "cases": null
                    }
                },
                ...
                "len": {
                    "values": [
                        0,
                        ...
                        118
                    ],
                    "type": "VariableFieldLenField",
                    "fuzzing": {
                        "fuzzer": null,
                        "cases": null
                    }
                }
            }
        }
    },
```
The fuzzer can be set to:
```json
"fuzzing": {
    "fuzzer": "scapy",
    "cases": null
}
```
In this case random values are choosen for the field.

The fuzzer can also be set to:
```json
"fuzzing": {
    "fuzzer": "radamsa",
    "cases": "packet"
}
```
In this case the general purpose fuzzer radamsa is used. This fuzzer is recommended for all fields with variable length. For MQTT these might for example be the topic or the message of an MQTTPublish. The fuzzer bases its random value on the value of the original package.

## Reading templates back in
The templates can be read using the method `readTeamplates()` of `mqtt_fuzzing.gen_template.TemplateReader`. It reads the templates from `config['Fuzzer']['Templates']`.
```
reader = TemplateReader()
templates = reader.readTeamplates()
```

## Fuzzing live traffic
To fuzz live traffic, take a look at the following snippet:
```python
import unittest
from mqtt_fuzzing.intercept import *
from mqtt_fuzzing.gen_template import *

class TestIntercept(unittest.TestCase):
    def setUp(self):
        reader = TemplateReader()
        self.templates = reader.readTeamplates()

    def test_intercept(self):
        c = ConnectionHandler()
        c.set_templates(self.templates)
        c.start()
```
The templates are read in as explained in the previous chapter. To intercept traffic a `ConnectionHandler()` is created and the templates are set.
Furthermore the Handler is started.

The `ConnectionHandler` automatically opens a socket on the port specified in `config['Broker']['Port']`.
Furthermore it creates an `MQTTAlive`, which checks if the broker and all registered clients are still alive or if a bug has been found.

For each new connection the ConnectionHandler creates a `MultInterceptor` and adds it to the list of clients in the `MQTTAlive`.

The `MultInterceptor` opens a `remote_socket` corresponding to the `local_socket`. The `remote_socket` handels the traffic to and from the broker, while the `local_socket` handels the traffic with the client.

The `MultInterceptor` checks if an SSL connection is handeled using the `config['Broker']['SSL']` attribute. If that is the case an SSL connection is opened in both directions using the certificates specified in the config.

The interceptor listens for traffic on both sockets. The TCP layer and all below are stripped away, the data is modified using the `modify()` method and is forwarded to the other device.

The modifing is mainly done in the `mqtt_fuzzing.fuzz.fuzz()` method. It matches each layer of the packet to its template:
```
layer = templates[(to_broker, type(payload).__name__)]
```
For each direction (to broker, from broker) there is another template.
For each field inside the layer the fuzzer looks in the templates and determines the fuzzing method. Currently are two methods implemented. These were explained in the chapter `Understand and Modify templates`.

If certain fields were not fuzzed they are recalculated to create valid packets:
```python
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
```
For MQTT the length fields need to be recalculated. The recalculation is handeld by `scapy`.

## MQTTAlive
MQTTAlive can be found in mqtt_fuzzing.mqtt_ping. It is used to check if the broker is still alive and to shutdown the fuzzer.
Two clients are created:
```python
client1 = paho.Client("heartbeatsub")
client2 = paho.Client("heartbeatpub")
```
The first client subscribes to the topic `heartbeat`. The second clients publishes packages to this topic in the interval specified in `config['Heartbeat']['Frequency']`.
If the second client does not receive a packet for a time of `config['Heartbeat']['Timeout']`. The fuzzer is stopped.
If a client does not send a message for `config['Heartbeat']['Timeout']`. The fuzzing is stopped as well. This is implemented in the `MultInterceptor`.


## General remarks
The program takes a black box approach to fuzz network systems. It can be adopted for other protocols.
The following parts, would need to be rewritten:
The recomputation needs to be adopted to recompute all lenth and checksum fields of the specific protocol. This part may be automated in future versions by including an attribute in the template which specifies which fields need recomputation.
The `MQTTAlive` is protocol specific. For other protocols, a specific methods to check if the system is alive needs to be implemented.

## Bugs found

When processing fields of variable length the broker Mosquitto and the Arduino MQTT library pubsubclient wait for further data.

- A common MQTT packet such as a publish packet is fuzzed. A length field e.g. the length field in the header is increased.
- The package is acknowledged on the TCP layer
- Their is no answer on the MQTT layer, a MQTTConnect is for example not answered with an MQTTConnAck
- The TCP session is not closed, as it is commonly done, when a faulty packet is received
- Further research needs to be done to validate the following attack
  - The memory to write the payload into (up to 256 MB) is reserved
  - Multiple connections are opened to the client / the broker
  - All of the memory is used up resulting in a DoS
