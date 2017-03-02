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
VALID_TOKEN_LEN = 8
MODULO_VALUES = [ 10**x for x in range(1,VALID_TOKEN_LEN) ]

# Dynamic Truncate function, as per RFC4226
def DT(hmac_hash):
    # compute dynamic binary code
    # extract the lower 4 bits from the last byte
    offset = hmac_hash[-1] & 0xf
    # extract 4 bytes from hmac_hash starting from offset
    dbc = hmac_hash[offset:offset + DBC_LEN]

    # assemble 4 bytes Dynamic Binary Code
    return struct.unpack(">I", dbc)[0] & 0x7fffffff

# compute modulo of byte value
def modulo(byte_string, token_len=6):
    # generate 6 digit HOTP code
    # (32bit value) mod 10^x where x is the code length
    # modulo
    mv = MODULO_VALUES[token_len - 1]

    # 4 bytes value
    bv = byte_string

    # compute HOTP value!
    # value is an integer
    return int(bv % mv)

# compute HOTP token as per RFC 4226
def HOTP(key, interval, digest=hashlib.sha1):
    # encode interval as unsigned int
    interval = interval if (isinstance(interval, bytes)) else struct.pack(">Q", interval)

    # compute HMAC-SHA-1 digest (20 bytes)
    hmac_hash = hmac.HMAC(key, interval, digest_function=digest)

    # compute Dynamic Truncation on the hmac value
    hotp = DT(hmac_hash)

    # return hotp value
    return modulo(hotp)
