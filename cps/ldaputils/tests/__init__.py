import unittest
import test_ldifanonymize

def test_all():
    suite = unittest.TestSuite()
    suite.addTest(test_ldifanonymize.test_suite())
    return suite
    
    
