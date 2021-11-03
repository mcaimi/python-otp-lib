#!/usr/bin/env python
# HMAC Test Vector
# Refer here for test vectors: https://datatracker.ietf.org/doc/html/rfc2104

import hashlib as hl
import rfc2104.hmac as hm
import pytest

# test vectors and expected results
test_vectors = {'case1':
                    {'key': b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b',
                     'data': 'Hi There',
                     'result_md5': '9294727a3638bb1c13f48ef8158bfc9d',
                     'result_sha1': '675b0b3a1b4ddf4e124872da6c2f632bfed957e9'},
                'case2':
                    {'key': 'Jefe',
                     'data': 'what do ya want for nothing?',
                     'result_md5': '750c783e6ab0b503eaa86e310a5db738',
                     'result_sha1': 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79'}
                }

# byte-string conversion test vectors
conv_test_vectors = {'sha1':
                        {'byte_rep': b'\xef\xfc\xdfj\xe5\xeb/\xa2\xd2t\x16\xd5\xf1\x84\xdf\x9c%\x9a|y',
                         'string_rep': 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79'},
                    'md5':
                        {'byte_rep': b'u\x0cx>j\xb0\xb5\x03\xea\xa8n1\n]\xb78',
                         'string_rep': '750c783e6ab0b503eaa86e310a5db738'}
                    }

# test HMAC routines with MD5 as digest function
def test_hmac_md5() -> bool:
    for k, v in test_vectors.items():
        k = v.get('key')
        m = v.get('data')
        r = v.get('result_md5')

        assert hm.hmac_to_string(hm.HMAC(k, m, digest_function=hl.md5)) == r


# test HMAC routines with SHA1 as digest function
def test_hmac_sha1() -> bool:
    for k, v in test_vectors.items():
        k = v.get('key')
        m = v.get('data')
        r = v.get('result_sha1')

        assert hm.hmac_to_string(hm.HMAC(k, m)) == r


# test HMAC bytes to string conversion
def test_hmac_to_string() -> bool:
    for k, v in conv_test_vectors.items():
        br = v.get('byte_rep')
        sr = v.get('string_rep')

        assert hm.hmac_to_string(br) == sr


# test HMAC string to bytes conversion
def test_string_to_hmac() -> bool:
    for k, v in conv_test_vectors.items():
        br = v.get('byte_rep')
        sr = v.get('string_rep')

        assert hm.string_to_hmac(sr) == br


# test exceptions
def test_hmac_to_str_wrong_input() -> bool:
    with pytest.raises(TypeError):
        hm.hmac_to_string("123")


def test_str_to_hmac_wrong_input() -> bool:
    with pytest.raises(TypeError):
        hm.string_to_hmac(123)
