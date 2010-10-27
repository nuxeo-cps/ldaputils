from setuptools import setup, find_packages
import sys, os

version = '0.0'

setup(name='cps.ldaputils',
      version=version,
      description="Various ldap utilities",
      long_description=open("README.txt").read() + "\n" +
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      classifiers=[
        'Topic :: System :: Systems Administration :: '
        'Authentication/Directory :: LDAP',
        'Topic :: Utilities',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Development Status :: 2 - Pre-Alpha',
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.3",
        ],
      keywords='ldap',
      author='CPS contributors',
      author_email='',
      url='http://hg.cps-cms.org/CPS/ldaputils',
      license='GPLv2',
      namespace_packages=['cps'],
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=['python-ldap',
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      test_suite="cps.ldaputils.tests.test_all"
      )
