#!/usr/bin/env python
from setuptools import setup, find_packages

# install OTP modules
setup(
        name="python-otp-lib",
        version="1.0",
        packages=find_packages(),
        author="Marco Caimi",
        author_email="mcaimi@redhat.com",
        description="A simple library that performs HOTP and TOTP token generation.",
        license="GPL v3",
        url="https://github.com/mcaimi/python-otp-lib.git"
)
