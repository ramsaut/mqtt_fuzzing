def goc(dic, key):
    print("{} {}".format(dic, key))
    if key not in dic:
        dic[key] = {}
    return dic[key]

def add_packet_to_templates(templates, to_broker, payload):
    while payload:

        layer = goc(templates, (to_broker, type(payload).__name__))
        payload.show()
        if 'fields' not in layer:
            fields = {}
            for fieldname, value in payload.fieldtype.items():
                print(fieldname)
                print(payload.fields)
                print(type(value).__name__)
                fields[fieldname] = {'values': set(), 'type': type(value).__name__,
                                     'fuzzing': {'fuzzer': None, 'cases': None}}
            layer['fields'] = fields

        print(templates)
        for fieldname, value in payload.fields.items():
            layer['fields'][fieldname]['values'].add(value)
        payload = payload.payload
