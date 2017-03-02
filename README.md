# OTP Token Generation Library, 100% Pure Python

This library implements functions that generate OTP Tokens based on RFC4226 (HOTP) and RFC 6238 (TOTP).

Additionally, the library implements a custom version of HMAC-SHA-1 that serves as a base for the mentioned algorithms (RFC 2104).

## HOW TO USE THIS LIBRARY:

## HMAC
The implementation default settings lets you compute HMAC-SHA-1 auth codes.
Generated HMAC codes are byte strings, so you need to convert them to something else if needed.

For example, if key="ORSXG5A=" and message=1234 (string and integer respectively), you need to only pack the message in a byte-like object:

    '''python
    \#!/usr/bin/env python
    import struct
    from rfc2104 import hmac
    
    key="ORSXG5A="
    msg=1234
    
    hmac = hmac.HMAC(key, struct.pack(">Q", msg))
    print(hmac)
    '''

the result is:
==> b'A3\x91v\xa5\xf7\xb0\xe5#\xb1\xa3\xa0a\xdf&\x13JC\x8ai'

## HOTP
The default implementation uses SHA-1 as the HMAC digest and an 8 byte unsigned integer as HOTP counter.
Internal conversions are automatically performed by the code.

    '''python
    \#!/usr/bin/env python
    from rfc4226 import hotp
    
    key = "ORSXG5A="
    msg = 1234
    
    hotp = hotp.HOTP(key, msg)
    print(hotp)
    '''

the result is:
==> 807009

## TOTP
TOTP is a special case of HOTP in which the counter is a 64bit unsigned timestamp.
The Google Authenticator implementation deviates from the RFC, because it expects the key to be encoded in base32.

    '''python
    \#!/usr/bin/env python
    from rfc6238 import totp
    import base64
    
    key = "ORSXG5A="
    msg = 1234
    
    totp = totp.TOTP(key)
    print(totp)
    
    google_key = base64.b32decode(key)
    google_totp = totp.TOTP(google_key)
    
    print(totp)
    print(google_totp)
      '''

the result is:
==> 426337
==> 234866



