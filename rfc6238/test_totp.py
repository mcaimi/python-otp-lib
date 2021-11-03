#!/usr/bin/env python
# TOTP Test Scenarios

import rfc6238.totp as totp
import base64

# test vectors
key = "ORSXG5A="
result_rfc = "285265"
result_google = "042328"


# test normalize
def test_normalize_string() -> bool:
    input_str = "String With Spaces"
    output_str = "StringWithSpaces"
    assert totp.normalize(input_str) == output_str


def test_normalize_bytes() -> bool:
    input_bytes = b'\x01 \x02 \x03'
    output_bytes = b'\x01\x02\x03'
    assert totp.normalize(input_bytes) == output_bytes


# test base32 decode
def test_base32_decode() -> bool:
    q = base64.b32decode(key, True)
    assert totp.base32_decode(key, True) == q


# test TOTP code generation
def test_google_totp_code_generation() -> bool:
    z = totp.TOTP(key, timecounter=-1, encode_base32=True)
    assert str(z) == result_google


def test_rfc_totp_code_generation() -> bool:
    z = totp.TOTP(key, timecounter=-1, encode_base32=False)
    assert str(z) == result_rfc


# test uri builder method
def test_uri_builder() -> bool:
    z = totp.TOTP(key, timecounter=-1)
    final_uri = "otpauth://totp/pytest?secret=042328&algorithm=SHA1&digits=6&period=30"
    assert totp.build_uri(z, "pytest") == final_uri
