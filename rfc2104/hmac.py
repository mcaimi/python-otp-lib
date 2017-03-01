#!/usr/bin/env python
#
#   HMAC generation library
#   Marco Caimi <marco.caimi@fastweb.it>
#
# import python libraries
import hashlib as hashes
try:
    import six
except ImportError as e:
    raise e

# constants
BLOCK_LEN = 64  # bytes
INNER_PAD = 0x36
OUTER_PAD = 0x5C

# calculate HMAC as per RFC2104
def HMAC(key, message, digest_function=hashes.sha1):
    # HMAC IS:
    #   H(key XOR OUTER_PAD, H(key XOR INNER_PAD, message))

    # check input type (must be UTF-8 encoded byte strings)
    key = str2unicode(key)
    message = str2unicode(message)

    # limit key length to SHA-1 hash size
    kl = len(key)
    pad = BLOCK_LEN - kl
    hmac_key = key if (kl <= BLOCK_LEN) else digest_function(key).digest()
    key_plaintext_array = [ x for x in hmac_key ] + [ 0x00 for i in range(0, pad) ]

    # compute inner element and hash
    inner_cyphertext = [ x ^ INNER_PAD for x in key_plaintext_array ]
    inner_element = bytes(inner_cyphertext) + message
    inner_hmac = digest_function(inner_element).digest()

    # compute outer element and hash
    outer_cypertext = [ x ^ OUTER_PAD for x in key_plaintext_array ]
    outer_element = bytes(outer_cypertext) + inner_hmac
    hmac = digest_function(outer_element).digest()

    # return computed HMAC
    return hmac

# convert a string into unicode bytes
def str2unicode(message):
    # convert string to unicode if needed
    if isinstance(message, six.string_types):
        message = message.encode('UTF-8')

    return message

