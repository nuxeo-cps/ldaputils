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

import sys

import ldap
from ldif import LDIFParser, LDIFWriter

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

    # This map has the following structure:
    # key:   a dictionary of (LDIF attribute name, LDIF attribute value)
    # value: new anonymized value
    anonymization_map = dict()

    counter = 0

    def __init__(self, input, output, target_attrs):
        LDIFParser.__init__(self, input)
        self.writer = LDIFWriter(output)
        self.target_attrs = target_attrs

    def anonymize(self, attr_name, attr_values):
        if attr_name.lower() not in self.target_attrs:
            return None

        # We have to make sure that attr_values is of the tuple type
        # because we want it to be hash-able.
        anonymization_map_key = (attr_name, tuple(attr_values))
        print "anonymization_map_key: %s" % str(anonymization_map_key)

        if anonymization_map_key not in self.anonymization_map:
            anonymized_value = str(self.counter)
            self.counter += 1
            self.anonymization_map[anonymization_map_key] = anonymized_value
        return anonymized_value

    def handle(self, dn, entry):
        dn_parts = ldap.dn.str2dn(dn)
        rdn = dn_parts[0]
        print "rdn: %s" % rdn

        # A RDN can be multi-valued
        anon_rdn = []
        for rdn_value in rdn:
            value = rdn_value[1]
            anon_value = self.anonymize(rdn_value[0], value)
            if anon_value is not None:
                value = anon_value
            anon_rdn.append((rdn_value[0], value, rdn_value[2]))
        dn_parts[0] = anon_rdn
        dn = ldap.dn.dn2str(dn_parts)

        for attr_name, attr_values in entry.items():
            anon_value = self.anonymize(attr_name, attr_values)
            if anon_value is not None:
                entry[attr_name] = [anon_value]
                print "modified entry: %s = %s" % (attr_name, str(entry[attr_name]))

        self.writer.unparse(dn, entry)

    def outputAnonymizationMap(self, output):
        for k, v in self.anonymization_map.items():
            output.write("%s -> %s\n" % (k, v))

if __name__ == '__main__':
    ldif_file_path = sys.argv[1]
    ldif_anonymized_file_path = ldif_file_path + '.anonym'
    anonymization_map_file_path = ldif_file_path + '.anonym.map'

    fin = open(ldif_file_path, 'r')
    fout = open(ldif_anonymized_file_path, 'wb')
    map_fout = open(anonymization_map_file_path, 'wb')

    parser = AnonymizingLdifParser(fin, fout, ATTRS_TO_ANONYMIZE)
    parser.parse()
    parser.outputAnonymizationMap(map_fout)
    fin.close()
    fout.close()
    map_fout.close()

