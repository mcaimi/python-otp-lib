#!/usr/bin/env python
#
#   HOTP Token generation as per RFC4226
#
import hashlib
import math
import six
import struct
try:
    from rfc2104 import hmac
except ImportError as e:
    raise e

# constants
DBC_LEN = 4     # bytes, dynamic binary code is 4 bytes per RFC
VALID_TOKEN_LEN = 8     # accept codes up to 8 characters
MODULO_VALUES = [ 10**x for x in range(1,VALID_TOKEN_LEN+1) ]

# Dynamic Truncate function, as per RFC4226
"""
    DT(hmac_hash)
        runs the Dynamic Truncation function (see RFC) on the hmac_hash.
        hmac_hash *must* be a bytestring object

    hmac_hash: HMAC byte string
"""
def DT(hmac_hash):
    if not isinstance(hmac_hash, six.binary_type):
        raise RuntimeError("hotp.DT(): Invalid HMAC hash. Expected [bytes], got [%s] instead." % type(hmac_hash))

    # compute dynamic binary code
    # extract the lower 4 bits from the last byte
    offset = (hmac_hash[-1] & 0xf) if six.PY3 else (ord(hmac_hash[-1]) & 0xf)
    # extract 4 bytes from hmac_hash starting from offset
    dbc = hmac_hash[offset:offset + DBC_LEN]

    # assemble 4 bytes Dynamic Binary Code
    # binary code is network-format packed (bigendian, convert back) and mask to get the 31 bits out
    return struct.unpack(">I", dbc)[0] & 0x7fffffff

# compute modulo of byte value
"""
    modulo(unsigned_int_value, token_len):
        executes a modulo operation on the unsigned_int_value (which is 32 bit long),
        extracting an integer value that has <token_len> cyphers

    unsigned_int_value: 32 bits, input value for the modulo operation
    token_len: default len of the output value. default is 6 cypher long
"""
def modulo(unsigned_int_value, token_len=6):
    # generate 6 digit HOTP code
    # (32bit value) mod 10^x where x is the code length
    # modulo
    if (token_len < 0) or (token_len > VALID_TOKEN_LEN):
        raise RuntimeError("Invalid token_len")

    # determine modulo operands
    mv = MODULO_VALUES[token_len - 1]

    # 4 bytes value
    bv = unsigned_int_value

    # compute HOTP value
    # value is an integer
    return int(bv % mv)

# compute HOTP token as per RFC 4226
"""
    HOTP(key, interval, digest)
        computes an HOTP token from the (key, interval) pair supplied in input

    key: shared secret, must be byte encoded (UTF-8)
    interval: 64bit unsigned integer value (network-format encoded)
    digest: hash algorithm to use when calculating the HMAC hash. default is SHA-1
"""
def HOTP(key, interval, digest=hashlib.sha1, token_len=6):
    # encode interval in unicode if needed
    interval = hmac.str2unicode(interval)

    # encode interval as unsigned int
    interval = interval if (isinstance(interval, bytes)) else struct.pack(">Q", interval)

    # compute HMAC-SHA-1 digest (20 bytes)
    hmac_hash = hmac.HMAC(key, interval, digest_function=digest)

    # compute Dynamic Truncation on the hmac value
    try:
        hotp = DT(hmac_hash)
    except RuntimeError as dt_exe:
        raise dt_exe

    # return hotp value
    return modulo(hotp, token_len=token_len)
