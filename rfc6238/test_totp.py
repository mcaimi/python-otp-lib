#!/usr/bin/env python
""" TOTP Test Scenarios """

import base64
from rfc6238 import totp

# test vectors
KEY = "ORSXG5A="
RESULT_RFC = "285265"
RESULT_GOOGLE = "042328"


def test_normalize_string() -> bool:
    """ string normalization test case """
    input_str = "String With Spaces"
    output_str = "StringWithSpaces"
    assert totp.normalize(input_str) == output_str


def test_normalize_bytes() -> bool:
    """ byte normalization test case """
    input_bytes = b'\x01 \x02 \x03'
    output_bytes = b'\x01\x02\x03'
    assert totp.normalize(input_bytes) == output_bytes


def test_base32_decode() -> bool:
    """ base32 decode test case """
    result = base64.b32decode(KEY, True)
    assert totp.base32_decode(KEY, True) == result


def test_google_totp_code_generation() -> bool:
    """ test TOTP token generation (google variant) """
    result = totp.totp(KEY, timecounter=-1, encode_base32=True)
    assert str(result) == RESULT_GOOGLE


def test_rfc_totp_code_generation() -> bool:
    """ test TOTP token generation (rfc variant) """
    result = totp.totp(KEY, timecounter=-1, encode_base32=False)
    assert str(result) == RESULT_RFC


def test_uri_builder() -> bool:
    """ uri_builder test case """
    result = totp.totp(KEY, timecounter=-1)
    final_uri = "otpauth://totp/pytest?secret=042328&algorithm=SHA1&digits=6&period=30"
    assert totp.build_uri(result, "pytest") == final_uri
