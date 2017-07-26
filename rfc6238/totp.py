#!/usr/bin/env python
#
#   TOTP Token Generation library (RFC6238)
#   v0.1 - Marco Caimi <marco.caimi@fastweb.it>
#
import struct
import hashlib
import six
import os
from math import floor
from time import time
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
"""
    normalize(key):
        strip away any whitespaces from a string or bytestring input

    key: the string to be processed. can be a 'str' or 'bytes' string
"""
def normalize(key):
    return key.replace(' ', '') if isinstance(key, str) else key.replace(b' ', b'')

# generate TOTP Token as per RFC 6238
"""
    TOTP(key, digest, timestep, timebase, encode_base32, casefold):
        computes a TOTP token based on the secret key and the current timestamp.

    key: shared secret. Input is a string, it is converted to UTF-8 bytestring automatically
    digest: hash to be used. by default SHA-1 is employed
    timestep: TOTP token period. default is 30 sec (Google Auth compatibility value)
    timebase: point in time from which we compute the timestamp in microseconds. default is 0
    encode_base32: if True the key is base32 encoded (Google auth), otherwise the key is left as is. default is True
    casefold: if True, base32 conversion is case-insensitive. defaults to True
"""
def TOTP(key, digest=hashlib.sha1, timestep=TS, timebase=0, encode_base32=True, casefold=True):
    # normalize and convert key in proper format
    key = hmac.str2unicode(key)
    key = normalize(key)

    # google wants the key to be base32 encoded...
    if (encode_base32):
        key = base64.b32decode(key, casefold=casefold)

    # compute timestamp and convert value in unsigned 64 bit integer
    T0 = 0 # unix epoch in RFC, 0 in google implementation
    now = floor((time() - T0)/timestep)

    # encode TC as unsigned 64bit integer
    tc = struct.pack(">Q", now)

    # compute HOTP(key, TC)
    totp_value = hotp.HOTP(key, tc, digest=digest)

    # return totp value
    return totp_value


"""
    get_random_base32_key(byte_len, digest)

    generates a new random base32-encoded key that can be used to generate TOTP codes.

    byte_len: how many random bytes to read from /dev/urandom
    digest: hash function to apply to the random bytearray before conversion
"""
def get_random_base32_key(byte_key=32, digest=hashlib.sha1):
    if six.PY3:
        random_b32 = base64.b32encode(digest(os.urandom(byte_len)).digest())
    else:
        random_b32 = six.b(str(base64.b32encode(digest(os.urandom(byte_len)).digest())))

    return random_b32

