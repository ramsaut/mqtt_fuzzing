# mqtt_led

Basic ESP8266 MQTT example

It connects to an MQTT server then:
  - publishes "hello world" to the topic "outTopic" every two seconds
  - subscribes to the topic "inTopic", printing out any messages
    it receives. NB - it assumes the received payloads are strings not binary
  - If the first character of the topic "inTopic" is an 1, switch ON the ESP Led,
    else switch it off

It will reconnect to the server if the connection is lost using a blocking reconnect function. 

Modify the project and add the right ssid and password, as well as the fuzzer as the mqtt server:

```
const char* ssid = "HERE_YOUR_SSID";
const char* password = "HERE_YOUR_PASSSWORD";
const char* mqtt_server = "123.123.123.123";
```

To install the ESP8266 board, (using Arduino 1.6.4+):

  - Add the following 3rd party board manager under "File -> Preferences -> Additional Boards Manager URLs":
       [http://arduino.esp8266.com/stable/package_esp8266com_index.json](http://arduino.esp8266.com/stable/package_esp8266com_index.json)
  - Open the "Tools -> Board -> Board Manager" and click install for the ESP8266"
  - Select your ESP8266 in "Tools -> Board"Installation

