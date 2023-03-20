#!/usr/bin/env python
import re
import os
import sys

from setuptools import setup


version_regex = r'__version__ = ["\']([^"\']*)["\']'
with open('mscerts/__init__.py') as f:
    text = f.read()
    match = re.search(version_regex, text)

    if match:
        VERSION = match.group(1)
    else:
        raise RuntimeError("No version number found!")

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist bdist_wheel upload')
    sys.exit()

setup(
    name='mscerts',
    version=VERSION,
    description='Python package for providing Microsoft\'s CA Bundle.',
    long_description=open('README.rst').read(),
    author='Ralph Broenink',
    author_email='ralph@ralphbroenink.net',
    url='https://github.com/ralphje/mscerts',
    packages=[
        'mscerts',
    ],
    package_dir={'mscerts': 'mscerts'},
    package_data={'mscerts': ['*.pem', '*.stl', 'py.typed']},
    include_package_data=True,
    extras_require={
        "stlupdate": ["requests", "signify", "asn1crypto"],
    },
    zip_safe=False,
    license='MPL-2.0',
    python_requires=">=3.6",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    project_urls={
        'Source': 'https://github.com/ralphje/mscerts',
    },
)
