#!/usr/bin/env python
#
#   TOTP Token Generation library (RFC6238)
#   v0.1 - Marco Caimi <marco.caimi@fastweb.it>
#
import struct
import hashlib
from math import floor
from datetime import datetime
try:
    from rfc4226 import hotp
except ImportError as e:
    raise e

# time step
# seconds, default value as per Google implementation
TS = 30

# strip whitespaces from key if any is present
def normalize(key):
    return key.replace(' ', '')

# generate TOTP Token as per RFC 6238
def TOTP(key, digest=hashlib.sha1, timestep=TS):
    # compute timestamp and convert value in unsigned 64 bit integer
    T0 = 0 # unix epoch
    now = floor((datetime.now().timestamp() - T0)/timestep)

    # encode TC as unsigned 64bit integer
    tc = struct.pack(">Q", now)

    # compute HOTP(key, TC)
    totp_value = hotp.HOTP(normalize(key), tc)

    # return totp value
    return totp_value

