#!/usr/bin/env python
#
#   HMAC generation library
#   Marco Caimi <mcaimi@redhat.com>
#
# import python libraries
import hashlib as hashes
import six
import struct

# constants
BLOCK_LEN = 64      # bytes
INNER_PAD = 0x36
OUTER_PAD = 0x5C

# calculate HMAC as per RFC2104
"""
    HMAC(key, message, digest_function, unicode_convert)
        Generates the HMAC code from the supplied (key,message) pair

    key: HMAC hashing key. Needs to be a byte-encoded string (UTF-8)
    message: Plaintext of the message you want to get the HMAC out of
    digest_function: Hashing algorithm to use to compute the HMAC. Default is SHA-1
    unicode_convert: If True, key and message parameters are automatically converted to UTF-8 bytestrings
"""
def HMAC(key, message, digest_function=hashes.sha1, unicode_convert=True):
    # HMAC IS:
    #   H(key XOR OUTER_PAD, H(key XOR INNER_PAD, message))

    if (unicode_convert):
        # check input type (must be UTF-8 encoded byte strings)
        key = str2unicode(key)
        message = str2unicode(message)

    # limit key length to SHA-1 hash size
    kl = len(key)
    pad = BLOCK_LEN - kl
    hmac_key = key if (kl <= BLOCK_LEN) else digest_function(key).digest()
    if not six.PY3:
        hmac_key = six.iterbytes(hmac_key)
        message = six.iterbytes(message)
    key_plaintext_array = ([ x for x in hmac_key ] + [ 0x00 for i in range(0, pad) ])

    # compute inner element and hash
    inner_cyphertext = [ x ^ INNER_PAD for x in key_plaintext_array ]
    if not six.PY3:
        inner_element = [ six.int2byte(x) for x in inner_cyphertext ] + [ six.int2byte(y) for y in message ]
        inner_element = ''.join(map(str, inner_element))
    else:
        inner_element = bytes(inner_cyphertext) + message
    # calculate inner hmac
    inner_hmac = digest_function(inner_element).digest()

    # compute outer element and hash
    outer_cyphertext = [ x ^ OUTER_PAD for x in key_plaintext_array ]
    if not six.PY3:
        outer_element = [ six.int2byte(x) for x in outer_cyphertext ] + [ six.b(str(inner_hmac)) ]
        outer_element = ''.join(map(str, outer_element))
    else:
        outer_element = bytes(outer_cyphertext) + inner_hmac
    hmac = digest_function(outer_element).digest()

    # return computed HMAC
    return hmac

# convert a string into unicode bytes
"""
    str2unicode(message):
        converts a python string into an UTF-8 encoded bytestring.

    message: string to be checked and converted

    output is always a string of BYTES.

"""
def str2unicode(message):
    # convert string to unicode if needed
    if isinstance(message, six.string_types):
        message = message.encode('UTF-8') if six.PY3 else six.b(str(message))

    return message

# returns a string representation of an HMAC bytestring
"""
    hmac_to_string(hmac, delimiter):
        returns a string representation of the HMAC bytestring supplied

    hmac: compute HMAC bytestring
    delimitier: delimiter character between hash digits. defaults is NUL
"""
def hmac_to_string(hmac, delimiter=""):
    if (isinstance(hmac, six.binary_type)):
        return delimiter.join(["%02x" % (x) for x in hmac]) if six.PY3 else delimiter.join(["%02x" % ord(x) for x in hmac])
    else:
        raise TypeError("hmac.hmac_to_string(): Incorrect input type. Expected [bytes], got [%s]" % hmac.__class__)

# returns a bytestring HMAC representation from an hex string hmac
"""
    string_to_hmac(str_hmac, delimiter):
        convert an hex string into a bytestring HMAC value

    str_hmac: HMAC in string format (hexadecimal)
    delimiter: hex values delimiter. default is NUL
"""
def string_to_hmac(str_hmac, delimiter=""):
    if (isinstance(str_hmac, six.string_types)):
        # remove delimiters if any
        if delimiter is not "":
            str_hmac = ''.join(str_hmac.split(delimiter)) if six.PY3 else ''.join(map(str, str_hmac.split(delimiter)))
        # rebuild bytestring
        return bytes([ x for x in [ int(str_hmac[y:y+2], 16) for y in range(0, len(str_hmac), 2)] ])
    else:
        raise TypeError("hmac.string_to_hmac(): Incorrect input type. Expected [str], got [%s]" % str_hmac.__class__)

