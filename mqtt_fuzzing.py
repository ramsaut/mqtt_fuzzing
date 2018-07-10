from scapy.contrib.mqtt import *
from mqtt_fuzzing.intercept import *
from mqtt_fuzzing.gen_template import *

generator = TemplateGenerator()
packets = generator.read_capture()
templates = generator.create_templates(packets)
generator.save_to_disk(templates)

reader = TemplateReader()
templates = reader.readTeamplates()
c = ConnectionHandler()
c.set_templates(templates)
c.start()
