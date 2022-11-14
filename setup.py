#!/usr/bin/env python3

'''Distribucion de RestFS Auth service'''

from setuptools import setup

setup(
    name='restfs-auth',
    version='0.1',
    description=__doc__,
    packages=['restfs_auth'],
    entry_points={
        'console_scripts': [
            'auth_service=restfs_auth.server:main'
        ]
    }
)