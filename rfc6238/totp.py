#!/usr/bin/env python
#
#   TOTP Token Generation library (RFC6238)
#   v0.1 - Marco Caimi <mcaimi@redhat.com>
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

import unicodedata
try:
    from urllib.parse import quote, urlencode
except ImportError:
    from urllib import quote, urlencode

# time step
# seconds, default value
TS = 30
# initial time. default is unix epoch
EPOCH = 0 # gmtime(0) or Midnight 1 Jan 1970

# strip whitespaces from key if any is present
"""
    normalize(key):
        strip away any whitespaces from a string or bytestring input

    key: the string to be processed. can be a 'str' or 'bytes' string
"""
def normalize(key):
    return key.replace(' ', '') if isinstance(key, str) else key.replace(b' ', b'')

# decode a base32 secret
"""
    base32_decode(key):
        decode a base32 encoded secret. 
        Ensure that the key is properly padded before calling b32decode

    key: secret string to be processed.
"""
def base32_decode(key, casefold=True):
    padlen = len(key) % 8

    if isinstance(key, str):
        key = hmac.str2unicode(key)

    if (padlen > 0):
        key += b'=' * (8 - padlen)

    return base64.b32decode(key, casefold=casefold)

# generate TOTP Token as per RFC 6238
"""
    TOTP(key, digest, timestep, timebase, encode_base32, casefold):
        computes a TOTP token based on the secret key and the current timestamp.

    key: shared secret. Input is a string, it is converted to UTF-8 bytestring automatically
    digest: hash to be used. by default SHA-1 is employed
    timecounter: point in time from epoch for which you want to compute the TOTP. (default is time.time())
    timestep: TOTP token period. default is 30 sec (Google Auth compatibility value)
    timebase: point in time from which we compute the timestamp in microseconds. default is EPOCH
    encode_base32: if True the key is base32 encoded (Google auth), otherwise the key is left as is. default is True
    casefold: if True, base32 conversion is case-insensitive. defaults to True
"""
def TOTP(key, timecounter=0, digest=hashlib.sha1, timestep=TS, timebase=EPOCH, encode_base32=True, casefold=True, token_len=6):
    # normalize and convert key in proper format
    key = normalize(key)
    # convert to unicode bytestring
    key = hmac.str2unicode(key)

    # google wants the key to be base32 encoded...
    if (encode_base32):
        key = base32_decode(key, casefold=casefold)

    # compute timestamp and convert value in unsigned 64 bit integer
    T0 = timebase # unix epoch in RFC
    if timecounter==0:
        now = floor(float(time() - T0)/timestep)
    else:
        now = floor(timecounter/timestep)

    # encode TC as unsigned 64bit integer
    tc = struct.pack(">Q", now)

    # compute HOTP(key, TC)
    totp_value = hotp.HOTP(key, tc, digest=digest, token_len=token_len)

    # HOTP result is an integer resulting from a modulo operation: check for result length
    # if less than 'token_len', left-pad with zeroes
    l = len(str(totp_value))
    if (l < token_len):
        totp_value = '0' * (token_len - l) + str(totp_value)

    # return totp value
    return totp_value


"""
    get_random_base32_key(byte_len, digest)

    generates a new random base32-encoded key that can be used to generate TOTP codes.

    byte_key: how many random bytes to read from /dev/urandom
    digest: hash function to apply to the random bytearray before conversion
"""
def get_random_base32_key(byte_key=32, digest=hashlib.sha1):
    if six.PY3:
        random_b32 = base64.b32encode(digest(os.urandom(byte_key)).digest())
    else:
        random_b32 = six.b(str(base64.b32encode(digest(os.urandom(byte_key)).digest())))

    return random_b32


"""
    Returns the provisioning URI for the OTP.

    See also:
        https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        adapted from pyotp library code

    secret: the totp secret used to generate the URI
    name: name of the account
    issuer_name: the name of the OTP issuer; this will be the organization title of the OTP entry in Authenticator
    algorithm: the algorithm used in the OTP generation.
    digits: the length of the OTP generated code.
    period: the number of seconds the OTP generator is set to expire every code.
"""

def build_uri(secret, name, issuer_name=None, digest=None, digits=None, period=None):
    # Handling values different from defaults
    chosen_digest = digest if (digest is not None and digest != 'sha1') else 'sha1'
    token_length = digits if (digits is not None and digits != 6) else 6
    token_ttl = period if (period is not None and period != 30) else 30

    # base OTP provisioning link structure
    base_uri = 'otpauth://{0}/{1}?{2}'

    url_args = {'secret': secret}

    label = quote(name)
    if issuer_name is not None:
        label = quote(issuer_name) + ':' + label
        url_args['issuer'] = issuer_name

    if chosen_digest:
        url_args['algorithm'] = chosen_digest.upper()
    if token_length:
        url_args['digits'] = token_length
    if token_ttl:
        url_args['period'] = token_ttl

    uri = base_uri.format('totp', label, urlencode(url_args).replace("+", "%20"))
    return uri

