#!/usr/bin/env python
#
# (C) Copyright 2010 JTEK <http://jtek.fr/>
# Authors:
# M.-A. Darche <ma.darche@cynode.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This program is an LDIF anonymizer

import logging

import sys

import ldap
from ldif import LDIFParser, LDIFWriter

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='ldifanonymize.log',
                    filemode='w')

def error(message):
    """Prints the message to stderr (and not stdout) and to the log
    """
    print >> sys.stderr, message
    logging.error(message)

def info(message):
    """Prints the message to stderr (and not stdout) and to the log
    """
    print >> sys.stderr, message
    logging.info(message)

def debug(message):
    """Prints the message only to the log
    """
    logging.debug(message)

ATTRS_TO_ANONYMIZE = (
    'uid', 'userid',
    'cn', 'commonname',
    'sn', 'surname',
    'givenname',
    'displayname',
    'l', 'localityname',
    'mail',
    'uid',
    'title',
    'employeenumber',
    'telephonenumber',
    'facsimiletelephonenumber',
    'description',
    'businesscategory',
    'roomnumber',
    'postaladdress',
    'userpassword',
)

class AnonymizingLdifParser(LDIFParser):

    # This dictionary has the following structure:
    # key:   a tuple of (LDIF attribute name, LDIF attribute value)
    # value: new anonymized value
    anonymization_map = dict()

    # Variable used to create new anonymized values
    counter = 0

    def __init__(self, input, output, target_attrs):
        LDIFParser.__init__(self, input)
        self.writer = LDIFWriter(output)
        self.target_attrs = target_attrs

    def anonymize(self, attr_name, attr_values):
        """Produces anonymized value and stores it in the anonymization_map.

        Returns None if the attr is not be anonymized.
        """
        if attr_name.lower() not in self.target_attrs:
            return None

        # We have to make sure that attr_values is of the tuple type
        # because we want it to be hash-able.
        anonymization_map_key = (attr_name, tuple(attr_values))
        debug("anonymization_map_key: %s" % str(anonymization_map_key))

        anonymized_value = self.anonymization_map.get(anonymization_map_key)
        if anonymized_value is None:
            anonymized_value = str(self.counter)
            if attr_name == 'mail':
                anonymized_value = 'a%s@example.net' % anonymized_value
            self.counter += 1
            self.anonymization_map[anonymization_map_key] = anonymized_value

        return anonymized_value

    def handle(self, dn, entry):
        """Reads entries from input LDIF file and writes to output LDIF file.
        """
        debug("processing: %s = %s" % (dn, entry))

        # This happens if the LDIF is, for example, the result of a ldapsearch
        if dn is None:
            return

        dn_parts = ldap.dn.str2dn(dn)
        rdn = dn_parts[0]
        debug("rdn: %s" % rdn)

        # A RDN can be multi-valued
        anon_rdn = []
        for rdn_value in rdn:
            value = rdn_value[1]
            anon_value = self.anonymize(rdn_value[0], [value])
            if anon_value is not None:
                value = anon_value
            anon_rdn.append((rdn_value[0], value, rdn_value[2]))
        dn_parts[0] = anon_rdn
        dn = ldap.dn.dn2str(dn_parts)

        for attr_name, attr_values in entry.items():
            anon_value = self.anonymize(attr_name, attr_values)
            if anon_value is not None:
                entry[attr_name] = [anon_value]
                debug("modified entry: %s = %s" %
                      (attr_name, str(entry[attr_name])))

        self.writer.unparse(dn, entry)

    def outputAnonymizationMap(self, output):
        output.write(repr(self.anonymization_map))

if __name__ == '__main__':
    ldif_file_path = sys.argv[1]
    ldif_anonymized_file_path = ldif_file_path + '.anonym'
    anonymization_map_file_path = ldif_file_path + '.anonym.map.py'

    fin = open(ldif_file_path, 'r')
    fout = open(ldif_anonymized_file_path, 'wb')
    map_fout = open(anonymization_map_file_path, 'wb')

    parser = AnonymizingLdifParser(fin, fout, ATTRS_TO_ANONYMIZE)
    parser.parse()
    parser.outputAnonymizationMap(map_fout)
    fin.close()
    fout.close()
    map_fout.close()
    info("Anonymizing done")

