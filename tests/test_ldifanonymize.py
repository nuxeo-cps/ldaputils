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
from filecmp import cmp

class TestCase(unittest.TestCase):

    ldif_file_path = 'files/sample.ldif'
    ldif_anon_file_path = ldif_file_path + '.anonym'
    anon_map_file_path = ldif_file_path + '.anonym.map.py'
    expected_ldif_anon_file_path = ldif_anon_file_path + '.expected'

    command = '../ldifanonymize.py %s' % (ldif_file_path)

    def testAnonymize(self):
        os.system(self.command)
        self.assert_(cmp(self.ldif_anon_file_path,
                         self.expected_ldif_anon_file_path))

if __name__ == '__main__':
    unittest.main()

