from setuptools import setup, find_packages
import sys, os

version = '0.0'

setup(name='signedheaders',
      version=version,
      description="Opencore signedheaders",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='David Turner',
      author_email='novalis@openplans.org',
      url='',
      license='GPLv3 or any later version',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
