#!/usr/bin/env python
#
#   TOTP Token Generation library (RFC6238)
#   v0.1 - Marco Caimi <marco.caimi@fastweb.it>
#
import struct
import hashlib
from math import floor
from datetime import datetime
import base64
try:
    from rfc4226 import hotp
    from rfc2104 import hmac
except ImportError as e:
    raise e

# time step
# seconds, default value as per Google implementation
TS = 30

# strip whitespaces from key if any is present
def normalize(key):
    return key.replace(' ', '') if isinstance(key, str) else key.replace(b' ', b'')

# generate TOTP Token as per RFC 6238
def TOTP(key, digest=hashlib.sha1, timestep=TS, encode_base32=True, casefold=True):
    # normalize and convert key in proper format
    key = hmac.str2unicode(key)
    key = normalize(key)

    # google wants the key to be base32 encoded...
    if (encode_base32):
        key = base64.b32decode(key, casefold=casefold)

    # compute timestamp and convert value in unsigned 64 bit integer
    T0 = 0 # unix epoch
    now = floor((datetime.now().timestamp() - T0)/timestep)

    # encode TC as unsigned 64bit integer
    tc = struct.pack(">Q", now)

    # compute HOTP(key, TC)
    totp_value = hotp.HOTP(key, tc)

    # return totp value
    return totp_value

