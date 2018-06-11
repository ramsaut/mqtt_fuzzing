# mqtt_fuzzing

## Installation
Install radamsa
https://github.com/aoh/radamsa

### Nutshell:

```
 $ sudo apt-get install gcc make git wget
 $ git clone https://github.com/aoh/radamsa.git && cd radamsa && make && sudo make install
 $ echo "HAL 9000" | radamsa
```

## Fields

Fields inside the packet can be marked for different purposes.

  * Fields can be used to match packets to templates e.g. packet type
  * Fields can be marked to be fuzzed
  * Fields can be recalculated after fuzzing e.g. checksums, length