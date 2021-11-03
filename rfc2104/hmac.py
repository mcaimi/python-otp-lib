#!/usr/bin/env python
#
#   HMAC generation library
#   Marco Caimi <mcaimi@redhat.com>
#
# calculate HMAC as per RFC2104

import hashlib as hashes
from typing import AnyStr, Callable

# constants
BLOCK_LEN: int = 64  # bytes
INNER_PAD: bytes = 0x36
OUTER_PAD: bytes = 0x5C

"""
    HMAC(key, message, digest_function, unicode_convert)
        Generates the HMAC code from the supplied (key,message) pair

    key:
        HMAC hashing key. Needs to be a byte-encoded string (UTF-8)
    message:
        Plaintext of the message you want to get the HMAC out of
    digest_function:
        Hashing algorithm to use to compute the HMAC. Default is SHA-1
"""


def HMAC(key: AnyStr, message: AnyStr, digest_function: Callable = hashes.sha1) -> bytes:
    # HMAC IS:
    #   H(key XOR OUTER_PAD, H(key XOR INNER_PAD, message))

    # check input type (must be UTF-8 encoded byte strings)
    key = str2bytes(key)
    message = str2bytes(message)

    # limit key length to SHA-1 hash size
    kl = len(key)
    pad = BLOCK_LEN - kl
    hmac_key = key if (kl <= BLOCK_LEN) else digest_function(key).digest()
    key_plaintext_array = ([x for x in hmac_key] + [0x00 for i in range(0, pad)])

    # compute inner element and hash
    inner_cyphertext = [x ^ INNER_PAD for x in key_plaintext_array]
    inner_element = bytes(inner_cyphertext) + message
    # calculate inner hmac
    inner_hmac = digest_function(inner_element).digest()

    # compute outer element and hash
    outer_cyphertext = [x ^ OUTER_PAD for x in key_plaintext_array]
    outer_element = bytes(outer_cyphertext) + inner_hmac
    hmac = digest_function(outer_element).digest()

    # return computed HMAC
    return hmac


"""
    str2bytes(message):
        converts a python string into an UTF-8 encoded bytestring.

    message:
        string to be checked and converted

    output is always a string of BYTES.

"""


def str2bytes(message: AnyStr) -> bytes:
    # convert string to unicode if needed
    if isinstance(message, str):
        message = message.encode('UTF-8')

    return message


"""
    hmac_to_string(hmac, delimiter):
        returns a string representation of the HMAC bytestring supplied

    hmac:
        computed HMAC bytestring
    delimitier:
        delimiter character between hash digits. defaults is an empty char
"""


def hmac_to_string(hmac: bytes, delimiter: str = "") -> str:
    if (isinstance(hmac, bytes)):
        return delimiter.join(["%02x" % (x) for x in hmac])
    else:
        raise TypeError("hmac.hmac_to_string(): Incorrect input type. Expected [bytes], got [%s]" % hmac.__class__)


"""
    string_to_hmac(str_hmac, delimiter):
        convert an hex string into a bytestring HMAC value

    str_hmac:
        HMAC in string format (hexadecimal)
    delimiter:
        hex values delimiter. default is an empty char
"""


def string_to_hmac(str_hmac: str, delimiter: str = "") -> bytes:
    if (isinstance(str_hmac, str)):
        # remove delimiters if any
        if delimiter != "":
            str_hmac = ''.join(str_hmac.split(delimiter))
        # rebuild bytestring
        return bytes([x for x in [int(str_hmac[y:y+2], 16) for y in range(0, len(str_hmac), 2)]])
    else:
        raise TypeError("hmac.string_to_hmac(): Incorrect input type. Expected [str], got [%s]" % str_hmac.__class__)
