# mqtt_fuzzing

## Installation
### Radamsa
https://github.com/aoh/radamsa

Nutshell:

```
 $ sudo apt-get install gcc make git wget
 $ git clone https://github.com/aoh/radamsa.git && cd radamsa && make && sudo make install
 $ echo "HAL 9000" | radamsa
```
### Requirements
```
 $ sudo apt install python3-dev libpcap0.8-dev libnetfilter-queue-dev
```

Setup python virtualenv with pip.
Activate the environment.
Install python requirements by executing:
```
pip install -r requirements.txt
```

## Fields

Fields inside the packet can be marked for different purposes.

  * Fields can be used to match packets to templates e.g. packet type
  * Fields can be marked to be fuzzed
  * Fields can be recalculated after fuzzing e.g. checksums, length