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

import unittest
import os
from StringIO import StringIO
from cps.ldaputils.ldifanonymize import (
    AnonymizingLdifParser,
    ATTRS_TO_ANONYMIZE,
)

TEST_DIR = os.path.split(__file__)[0]

class LdifAnonTestCase(unittest.TestCase):

    ldif_file_path = os.path.join(TEST_DIR, 'files', 'sample.ldif')
    ldif_anon_file_path = ldif_file_path + '.anonym'
    anon_map_file_path = ldif_file_path + '.anonym.map.py'
    expected_ldif_anon_file_path = ldif_anon_file_path + '.expected'

    command = '../ldifanonymize.py %s' % (ldif_file_path)

    def testAnonymize(self):
        fin = open(self.ldif_file_path)
        fout = StringIO()
        parser = AnonymizingLdifParser(fin, fout, ATTRS_TO_ANONYMIZE)
        parser.parse()

        # parser.outputAnonymizationMap(map_fout)
        expected = open(self.expected_ldif_anon_file_path)
        self.assertEquals(fout.getvalue(), expected.read())
        expected.close()
        fin.close()

def test_suite():
    return unittest.makeSuite(LdifAnonTestCase)

if __name__ == '__main__':
    unittest.main()

