#!/usr/bin/env python
""" HOTP Test Scenarios
Refer here for test vectors: https://datatracker.ietf.org/doc/html/rfc4226 """

import pytest
from rfc4226 import hotp

# test vectors
SECRET_KEY = "3132333435363738393031323334353637383930"
secret_bytes = bytes.fromhex(SECRET_KEY)
test_vectors = {0: 755224,
                1: 287082,
                2: 359152,
                3: 969429,
                4: 338314,
                5: 254676,
                6: 287922,
                7: 162583,
                8: 399871,
                9: 520489
                }


def test_dynamic_truncate_runtime_error() -> bool:
    """ Test Exception Handling """
    integer_value = 1234
    with pytest.raises(RuntimeError):
        hotp.dynamic_truncate(integer_value)


def test_modulo_error_invalid_input_type() -> bool:
    """ Test Modulo operation error handling with wrong string input """
    string_value = "Wrong_Input"
    with pytest.raises(RuntimeError):
        hotp.modulo(string_value)


def test_modulo_error_invalid_token_len() -> bool:
    """ Test Modulo operation error handling with wrong byte input """
    int_value = 255
    with pytest.raises(RuntimeError):
        hotp.modulo(b'input', int_value)


def test_hmac_codes_generation() -> bool:
    """ HOTP codes generation tests """
    for key, value in test_vectors.items():
        hotp_token = hotp.hotp(secret_bytes, key)
        assert hotp_token == value
