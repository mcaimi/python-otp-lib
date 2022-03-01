#!/usr/bin/env python
#
#   HMAC generation library
#   Marco Caimi <mcaimi@redhat.com>
#
''' calculate HMAC as per RFC2104 '''

import hashlib as hashes
from typing import AnyStr, Callable

# constants
BLOCK_LEN: int = 64  # bytes
INNER_PAD: bytes = 0x36
OUTER_PAD: bytes = 0x5C


def hmac(key: AnyStr, message: AnyStr, digest_function: Callable = hashes.sha1) -> bytes:
    """
        hmac(key, message, digest_function, unicode_convert)
            Generates the hmac code from the supplied (key,message) pair

        key:
            hmac hashing key. Needs to be a byte-encoded string (UTF-8)
        message:
            Plaintext of the message you want to get the hmac out of
        digest_function:
            Hashing algorithm to use to compute the hmac. Default is SHA-1
    """

    # hmac IS:
    #   H(key XOR OUTER_PAD, H(key XOR INNER_PAD, message))

    # check input type (must be UTF-8 encoded byte strings)
    key = str2bytes(key)
    message = str2bytes(message)

    # limit key length to SHA-1 hash size
    key_len = len(key)
    pad = BLOCK_LEN - key_len
    hmac_key = key if (key_len <= BLOCK_LEN) else digest_function(key).digest()
    key_plaintext_array = (list(hmac_key) + [0x00 for i in range(0, pad)])

    # compute inner element and hash
    inner_cyphertext = [x ^ INNER_PAD for x in key_plaintext_array]
    inner_element = bytes(inner_cyphertext) + message
    # calculate inner hmac
    inner_hmac = digest_function(inner_element).digest()

    # compute outer element and hash
    outer_cyphertext = [x ^ OUTER_PAD for x in key_plaintext_array]
    outer_element = bytes(outer_cyphertext) + inner_hmac
    hmac_digest = digest_function(outer_element).digest()

    # return computed hmac
    return hmac_digest


def str2bytes(message: AnyStr) -> bytes:
    """
        str2bytes(message):
            converts a python string into an UTF-8 encoded bytestring.

        message:
            string to be checked and converted

        output is always a string of BYTES.

    """

    # convert string to unicode if needed
    if isinstance(message, str):
        message = message.encode('UTF-8')

    return message


def hmac_to_string(hmac_digest: bytes, delimiter: str = "") -> str:
    """
        hmac_to_string(hmac, delimiter):
            returns a string representation of the HMAC bytestring supplied

        hmac:
            computed HMAC bytestring
        delimitier:
            delimiter character between hash digits. defaults is an empty char
    """

    if isinstance(hmac_digest, bytes):
        return delimiter.join([f"{x:02x}" for x in hmac_digest])

    raise TypeError(f"hmac.hmac_to_string(): Incorrect input type.\
            Expected [bytes], got {hmac.__class__}")


def string_to_hmac(str_hmac: str, delimiter: str = "") -> bytes:
    """
        string_to_hmac(str_hmac, delimiter):
            convert an hex string into a bytestring HMAC value

        str_hmac:
            HMAC in string format (hexadecimal)
        delimiter:
            hex values delimiter. default is an empty char
    """

    if isinstance(str_hmac, str):
        # remove delimiters if any
        if delimiter != "":
            str_hmac = ''.join(str_hmac.split(delimiter))
        # rebuild bytestring
        return bytes(list(int(str_hmac[y: y + 2], 16) for y in range(0, len(str_hmac), 2)))

    raise TypeError(f"hmac.string_to_hmac(): Incorrect input type.\
            Expected [str], got {str_hmac.__class__}")
