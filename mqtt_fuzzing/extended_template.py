from polymorph.template import Template
import json
from polymorph.tlayer import TLayer
from polymorph.tfield import TField
from polymorph.tlist import TList
from collections import OrderedDict
from datetime import datetime
from os.path import dirname
import polymorph.conditions
import os

class FuzzingTemplate(Template):
    """Class that represents a template. It adds the fuzzing fields to a common polymorph template"""
    def __init__(self, from_path):
        super().__init__(from_path=from_path)

    def read(self, path):
        """Reads a `Template` from disk.

        Parameters
        ----------
        path: str
            Path from which the template will be read.

        """
        with open(path) as t:
            template = json.load(t)
        # Reading layers
        self._name = template['Name']
        self._version = template['Version']
        self._timestamp = template['Timestamp']
        self._description = template['Description']
        self._raw = template['raw']
        self._functions = template['Functions']
        for layer in template['layers']:
            l = TLayer(layer['name'],
                       raw=self._raw,
                       lslice=layer['lslice'],
                       custom=layer['custom'])
            # Reading the structs
            structs = layer["structs"]
            # Reading fields
            for field in layer['fields']:
                ftype = field['type']
                if ftype[0] == str(int):
                    ftype = (int, ftype[1])
                elif ftype[0] == str(str):
                    ftype = (str, ftype[1])
                elif ftype[0] == str(bytes):
                    ftype = (bytes, ftype[1])
                f = TField(name=field['name'],
                           value=bytearray.fromhex(field['value']),
                           raw=self._raw,
                           tslice=field['slice'],
                           custom=field['custom'],
                           size=field['size'],
                           ftype=ftype,
                           frepr=field['frepr']) # Added fuzzing field here
                f.fuzzing = field['fuzzing']
                f.layer = l
                l.addfield(f)
            # Initialization of the structs
            for f in structs:
                l.add_struct(f,
                             structs[f]['fdeps'],
                             structs[f]['sb'],
                             structs[f]['exp'])
            self.addlayer(l)

    def dict(self):
        return dict_template(self)


def write_template(template, path=None):
    """Writes a `Template` to disk.

    Parameters
    ----------
    path : str, optional
        Path where the `Template` will be written, if None
        the `Template` will be written in templates folder.

    """
    if not path:
        path = "../templates/" + template._name.replace("/", "_") + ".json"
    with open(path, 'w') as outfile:
        json.dump(dict_template(template), outfile, indent=4)


def dict_template(template):
    """Build a dictionary with all the elements of the `Template`.

    Returns
    -------
    :obj:`dict`
        Dictionary with all the fields and layers of the template.

    """

    d = OrderedDict([("Name", template._name),
                     ("Description", template._description),
                     ("Version", template._version),
                     ("Timestamp", template._timestamp),
                     ("Functions", template._functions),
                     ("layers", [l.dict() for l in template._layers.values()]),
                     ("raw", template._raw), ])

    for l in d["layers"]:
        for f in l["fields"]:
            if 'fuzzing' not in f:
                f['fuzzing'] = None

    return d


class FuzzingTList(TList):
    def __init__(self, tlist):
        self._tgen = tlist._tgen
        self._len = tlist._len
        self._names = tlist._names
        self._templates = tlist._templates


    def write(self, path="../templates"):
        """Writes `TemplateList` to disk.

        Notes
        -----
        Because the templates are generated in execution time when they are
        accessed, if the user has already accessed some, they are not
        generated again, and they are generated from that point.

        Parameters
        ----------
        path : str
            The path where the `Template` will be written.

        """
        self._generate_templates()
        for t in self._templates:
            if not path:
                path = "../templates/" + t._name.replace("/", "_") + ".json"
            with open(path, 'w') as outfile:
                json.dump(dict_template(t), outfile, indent=4)