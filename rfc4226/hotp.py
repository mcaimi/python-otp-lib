#!/usr/bin/env python
#
#   HOTP Token generation as per RFC4226
#
import hashlib
import math
import struct
try:
    from rfc2104 import hmac
except ImportError as e:
    raise e

# constants
DBC_LEN = 4

# Dynamic Truncate function, as per RFC4226
def DT(hmac_hash):
    # compute dynamic binary code
    # extract the lower 4 bits from the last byte
    offset = hmac_hash[-1] & 0xf
    # extract 4 bytes from hmac_hash starting from offset
    dbc_array = [ hmac_hash[i] for i in range(offset, offset + DBC_LEN) ]
    # mask the first byte, discart most significant bit
    dbc_array[0] &= 0x7f

    # assemble 4 bytes Dynamic Binary Code
    return bytes(dbc_array)

# compute modulo of byte value
def modulo(byte_string, exponent=6):
    # generate 6 digit HOTP code
    # (32bit value) mod 10^x where x is the code length
    mv = math.pow(10,exponent)

    # unpack 4 bytes value into a 32bit integer
    # unpack returns a tuple, get first value
    bv = struct.unpack("i", byte_string)[0]

    # return HOTP value!
    # value is an integer
    return int(bv % mv)

# compute HOTP token as per RFC 4226
def HOTP(key, message, digest=hashlib.sha1):
    # compute HMAC-SHA-1 digest (20 bytes)
    hmac_hash = hmac.HMAC(key, message, digest_function=digest)

    # compute Dynamic Truncation on the hmac value
    hotp = DT(hmac_hash)

    # return hotp value
    return modulo(hotp)
